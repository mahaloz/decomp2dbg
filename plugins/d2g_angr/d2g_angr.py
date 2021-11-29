#
# ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ███████╗███████╗
# ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔══██╗╚════██╗██╔════╝ ██╔════╝██╔════╝
# ██║  ██║█████╗  ██║     ██║   ██║██╔████╔██║██████╔╝ █████╔╝██║  ███╗█████╗  █████╗
# ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔═══╝ ██║   ██║██╔══╝  ██╔══╝
# ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗╚██████╔╝███████╗██║
# ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚══════╝╚═╝
#                            angr-management server
#
# by clasm, 2021.
#

from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import threading
import os

#
# Decompilation API
#

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class Decomp2GefPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        """
        The entry point for the Decomp2Gef plugin.
        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)
        self.HOST, self.PORT = "0.0.0.0", 3662
        self.DEBUG = True
        self._workspace = workspace
        self._instance = workspace.instance

        self.xmlrpc_thread = threading.Thread(target=self.start_xmlrpc_server, args=())
        self.xmlrpc_thread.setDaemon(True)
        self._workspace.log("[+] Creating new thread for XMLRPC server: {}".format(self.xmlrpc_thread.name))
        self.xmlrpc_thread.start()


    #
    # XMLRPC Server Code
    #



    def ping(self):
        return True


    def start_xmlrpc_server(self):
        """
        Initialize the XMLRPC thread.
        """
        server = SimpleXMLRPCServer(
            (self.HOST, self.PORT),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        server.register_introspection_functions()
        server.register_function(self.decompile)
        server.register_function(self.global_info)
        server.register_function(self.ping)
        while True:
            server.handle_request()

        return

    def _get_all_func_info(self):
        resp = {"function_headers": {}}
        for addr, func in self._instance.kb.functions.items():
            func_info = {
                "name": func.name,
                "base_addr": addr,
                "size": func.size
            }
            resp[func.name] = func_info
        return resp

    def global_info(self):
        resp = {}
        # function names, addrs, sizes
        resp.update(self._get_all_func_info())
        return resp

    #### THIS FUNCION WAS TAKEN DIRECTLY FROM BINSYNC
    def decompile_function(self, func):
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

    def decompile(self, addr: int):
        resp = {"code": None}
        self._workspace.log(f"Attempting decompile for {hex(addr)}")
        if addr < self._instance.project.loader.min_addr:
            addr += self._instance.project.loader.min_addr

        func_addr = self._instance.cfg.get_any_node(addr, anyaddr=True).function_address
        func = self._instance.kb.functions[func_addr]
        decomp = self.decompile_function(func)
        pos = decomp.map_addr_to_pos.get_nearest_pos(addr)
        size = len(decomp.text)
        line_end = decomp.text.find("\n", pos)
        line_start = size - decomp.text[::-1].find("\n", size - line_end)
        decomp_lines = decomp.text.split('\n')
        for idx, line in enumerate(decomp_lines):
            if decomp.text[line_start:line_end] in line:
                break
        else:
            return resp

        resp["code"] = decomp_lines
        resp["func_name"] = func.name
        resp["line"] = idx
        return resp