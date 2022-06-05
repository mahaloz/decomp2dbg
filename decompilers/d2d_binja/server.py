from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from binaryninja import SymbolType, EntryRegisterValue
from binaryninja.binaryview import BinaryDataNotification
import binaryninja

#
# Binja Hooks
#


class DataNotification(BinaryDataNotification):
    def __init__(self, bv, server):
        super().__init__()
        self.bv = bv
        self.server = server  # type: BinjaDecompilerServer

    def symbol_updated(self, view, sym):
        if sym.type == SymbolType.FunctionSymbol:
            self.server.cache["function_headers"][str(sym.address)]["name"] = sym.name
        elif sym.type == SymbolType.DataSymbol:
            self.server.cache["global_vars"][str(sym.address)]["name"] = sym.name

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
            "reg_vars": {},
            "stack_vars": {}
        }

        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return resp

        func = funcs[0]

        # get stack frame offset for x86
        frame_offset = 0
        if self.bv.arch.name == 'x86_64':
            frame_offset -= self.bv.arch.address_size
        elif self.bv.arch.name == 'x86':
            # handle inconsistent stack frame offsets
            current_frame = func.get_reg_value_at(addr, 'ebp')
            if current_frame.type != EntryRegisterValue.type:
                frame_offset = current_frame.value

        # get stack vars
        stack_vars = {}
        for stack_var in func.stack_layout:
            offset = frame_offset - stack_var.storage
            stack_vars[str(offset)] = {
                "name": stack_var.name,
                "type": str(stack_var.type)
            }

        # get reg vars
        reg_vars = {}
        for var in func.vars:
            if var.source_type != binaryninja.VariableSourceType.RegisterVariableSourceType or not var.name:
                continue

            reg_vars[var.name] = {
                "reg_name": self.bv.arch.get_reg_name(var.storage),
                "type": str(var.type)
            }

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

            resp[str(func.start)] = {
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

            resp[str(addr)] = {
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
        server.register_function(self.ping)
        print("[+] Registered decompilation server!")
        while True:
            server.handle_request()
