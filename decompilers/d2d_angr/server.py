from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import os
import sys

import angr
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator



class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class AngrDecompilerServer:
    def __init__(self, instance, host="localhost", port=3662):
        self._instance = instance
        self._workspace = self._instance.workspace
        self.host = host
        self.port = port

    #
    # Private
    #

    def rebase_addr(self, addr, down=False):
        rebased = addr
        base_addr = self._instance.project.loader.min_addr

        if down:
            rebased -= base_addr
        elif addr < base_addr:
            rebased += base_addr

        return rebased

    def _decompile_function(self, func):
        """
        Taken directly from BinSync
        """
        # check for known decompilation
        available = self._instance.kb.structured_code.available_flavors(func.addr)
        should_decompile = False
        if 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self._instance.kb.structured_code[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        if should_decompile:
            # recover direct pseudocode
            self._instance.project.analyses.Decompiler(func, flavor='pseudocode')

            # attempt to get source code if its available
            source_root = None
            if self._instance.original_binary_path:
                source_root = os.path.dirname(self._instance.original_binary_path)
            self._instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

        # grab newly cached pseudocode
        decomp = self._instance.kb.structured_code[(func.addr, 'pseudocode')].codegen
        return decomp

    #
    # Public API
    #

    def decompile(self, addr: int):
        """
        Takes an addr which may be in a function. If addr is not in a function, a dict with the defined
        parameters below should be returned with None for each value. Decompilation should be the decompilation
        string of the function. curr_line should be the line number of that decompilation, starting at 0.

        Always returns a dict with the defined keys below, which may have None as their values.
        """
        resp = {
            "decompilation": None
        }

        addr = self.rebase_addr(addr)
        func_addr = self._instance.cfg.get_any_node(addr, anyaddr=True).function_address
        func = self._instance.kb.functions[func_addr]
        decomp = self._decompile_function(func)
        try:
            pos = decomp.map_addr_to_pos.get_nearest_pos(addr)
        except Exception as e:
            print(f"Failed to get nearest pos: {e} for {hex(addr)}, skipping decomp")
            return resp

        size = len(decomp.text)
        line_end = decomp.text.find("\n", pos)
        line_start = size - decomp.text[::-1].find("\n", size - line_end)
        decomp_lines = decomp.text.split('\n')
        for idx, line in enumerate(decomp_lines):
            if decomp.text[line_start:line_end] in line:
                break
        else:
            return resp

        resp["decompilation"] = decomp_lines
        resp["func_name"] = func.name
        resp["curr_line"] = idx
        return resp

    def function_data(self, addr: int):
        """
        Returns stack vars and func args

        """
        resp = {
            "reg_vars": [],
            "stack_vars": []
        }

        addr = self.rebase_addr(addr)
        func_addr = self._instance.cfg.get_any_node(addr, anyaddr=True).function_address
        func = self._instance.kb.functions[func_addr]
        decomp = self._decompile_function(func)
        manager = decomp.cfunc.variable_manager
        for var in manager._unified_variables:
            if isinstance(var, angr.sim_variable.SimStackVariable):
                resp["stack_vars"].append({
                    "name": var.name,
                    "type": manager.get_variable_type(var).c_repr(),
                    # offset from frame base
                    "from_frame": str(var.offset),
                    "from_sp": None,
                })

        return resp

    def function_headers(self):
        resp = {}
        for addr, func in self._instance.kb.functions.items():
            resp[str(self.rebase_addr(addr, down=True))] = {
                "name": func.name,
                "size": func.size
            }

        return resp

    def global_vars(self):
        resp = {}

        return resp

    def structs(self):
        resp = {}

        return resp

    def breakpoints(self):
        resp = {}

        return resp

    def binary_path(self) -> str:
        """
        Get the filesystem path of the binary being decompiled.
        """
        return self._instance.project.loader.main_object.binary

    def versions(self) -> dict[str, str]:
        """
        Get version information about the decompiler environment.
        """
        return {
            "name": "angr",
            "version": angr.__version__,
            "python": sys.version,
        }


    def focus_address(self, addr: int) -> bool:
        """
        Focus the given address in the GUI of the decompiler. If possible,
        don't switch the window focus.

        Returns:
            True if successful, otherwise False
        """
        self._workspace.jump_to(self.rebase_addr(addr))
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
