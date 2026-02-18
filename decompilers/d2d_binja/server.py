from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import sys

from binaryninja import SymbolType, EntryRegisterValue
from binaryninja.binaryview import BinaryDataNotification
import binaryninja


def rebase_addr(bv, addr: int, rebase_down: bool = False) -> int:
    base = bv.start
    rebased_addr = addr
    if rebase_down:
        rebased_addr -= base
    elif addr < base:
        rebased_addr += base
    return rebased_addr

#
# Binja Hooks
#


class DataNotification(BinaryDataNotification):
    def __init__(self, bv, server):
        super().__init__()
        self.bv = bv
        self.server = server  # type: BinjaDecompilerServer

    def symbol_updated(self, view, sym):
        sym_addr: str = str(rebase_addr(self.bv, sym.address, rebase_down=True))
        if sym.type == SymbolType.FunctionSymbol:
            self.server.cache["function_headers"][sym_addr]["name"] = sym.name
        elif sym.type == SymbolType.DataSymbol:
            self.server.cache["global_vars"][sym_addr]["name"] = sym.name

#
# Server Code
#


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class BinjaDecompilerServer:
    def __init__(self, bv, host=None, port=None):
        self.bv = bv
        self.host = host
        self.port = port

        # save the last line for bugging decomp mapping
        self._last_line = 0

        # cache changes so we don't need to regen content
        self.cache = {
            "global_vars": None,
            "function_headers": None
        }

        # make the server init cache data once
        self.function_headers()
        self.global_vars()

        # init hooks for cache
        notification = DataNotification(self.bv, self)
        self.bv.register_notification(notification)


    #
    # Public API
    #

    def decompile(self, addr: int):
        resp = {
            "decompilation": None,
            "curr_line": None,
            "func_name": None
        }
        addr = rebase_addr(self.bv, addr)
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return resp
        func = funcs[0]

        decomp = str(func.hlil).split("\n")
        if not decomp:
            return resp

        resp["decompilation"] = decomp
        resp["func_name"] = func.name

        # find the decompiled line closest to the current addr
        decomp_lines = func.get_low_level_il_at(addr).hlils
        if not decomp_lines:
            resp["curr_line"] = self._last_line
            return resp

        best_line = min(decomp_lines, key=lambda l: abs(l.address - addr))

        resp["curr_line"] = best_line.instr_index
        self._last_line = resp["curr_line"] if resp["curr_line"] != 0 else self._last_line
        return resp

    def function_data(self, addr: int):
        """
        Returns stack vars and func args

        """
        resp = {
            "reg_vars": [],
            "stack_vars": []
        }

        addr = rebase_addr(self.bv, addr)
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return resp

        func = funcs[0]

        # get stack vars
        stack_vars = []
        for stack_var in func.stack_layout:
            # https://api.binary.ninja/binaryninja.variable-module.html#corevariable
            # Doesn't really specify, but the offset is from the frame ptr (near ret addr).
            # The value is negative, so we flip it.
            stack_vars.append({
                "name": stack_var.name,
                "type": str(stack_var.type),
                "from_sp": None,
                "from_frame": str(-stack_var.storage),
            })

        # get reg vars
        reg_vars = []
        for var in func.vars:
            if var.source_type != binaryninja.VariableSourceType.RegisterVariableSourceType or not var.name:
                continue

            reg_vars.append({
                "name": var.name,
                "type": str(var.type),
                "reg_name": self.bv.arch.get_reg_name(var.storage),
            })

        resp["reg_vars"] = reg_vars
        resp["stack_vars"] = stack_vars

        return resp

    def function_headers(self):
        # check if a cache is available
        cache_headers = self.cache["function_headers"]
        if cache_headers:
            return cache_headers

        resp = {}
        for func in self.bv.functions:

            # Skip everything besides FunctionSymbol
            if func.symbol.type != SymbolType.FunctionSymbol:
                continue

            resp[str(rebase_addr(self.bv, func.start, True))] = {
                "name": func.name,
                "size": func.total_bytes
            }

        self.cache["function_headers"] = resp
        return resp

    def global_vars(self):
        # check if a cache is available
        cache_globals = self.cache["global_vars"]
        if cache_globals:
            return cache_globals

        resp = {}
        for addr, var in self.bv.data_vars.items():
            sym = self.bv.get_symbol_at(addr)
            name = sym.name if sym else "data_{:x}".format(addr)

            resp[str(rebase_addr(self.bv, addr, True))] = {
                "name": name
            }

        self.cache["global_vars"] = resp
        return resp

    def structs(self):
        resp = {}
        """
        # tuple of structure name and StructureType
        for t in self.bv.types.items():
            struct_name = t[0]
            struct = t[1]
            resp[struct_name] = {
                "size": struct.width
            }
            for member in struct.members:
                resp[struct_name][member.name] = {
                    "offset": member.offset,
                    "size": len(member)
                }
        """

        return resp

    def breakpoints(self):
        resp = {}
        return resp

    def binary_path(self) -> str:
        """
        Get the filesystem path of the binary being decompiled.
        """
        return self.bv.file.original_filename

    def versions(self) -> dict[str, str]:
        """
        Get version information about the decompiler environment.
        """
        resp = {
            # the name of the decompiler
            "name": "binaryninja",
            # the version of the decompiler
            "version": binaryninja.core_version(),
            # the version of the runtime it uses
            "python": sys.version,
        }
        return resp

    def focus_address(self, addr: int) -> bool:
        """
        Focus the given address in the GUI of the decompiler. If possible,
        don't switch the window focus.

        Returns:
            True if successful, otherwise False
        """
        
        addr = rebase_addr(self.bv, addr)
        self.bv.navigate(self.bv.view, addr)
        return True

    #
    # XMLRPC Server
    #

    def ping(self):
        return True

    def start_xmlrpc_server(self, host="localhost", port=3662):
        """
        Initialize the XMLRPC thread.
        """
        host = host or self.host
        port = port or self.port

        print("[+] Starting XMLRPC server: {}:{}".format(host, port))
        server = SimpleXMLRPCServer(
            (host, port),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        server.register_introspection_functions()
        server.register_function(self.decompile)
        server.register_function(self.function_headers)
        server.register_function(self.function_data)
        server.register_function(self.global_vars)
        server.register_function(self.structs)
        server.register_function(self.breakpoints)
        server.register_function(self.binary_path)
        server.register_function(self.versions)
        server.register_function(self.focus_address)
        server.register_function(self.ping)
        print("[+] Registered decompilation server!")
        while True:
            server.handle_request()
