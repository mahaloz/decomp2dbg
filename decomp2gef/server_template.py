from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
HOST, PORT = "0.0.0.0", 3662


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class DecompilerServer:

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
            "decompilation": str,
            "curr_line": int,
            "func_name": str
        }

        return resp

    def function_data(self, addr: int):
        """
        Returns stack vars and func args

        """
        resp = {
            "args": {
                0x0: {
                    "name": "example_name",
                    "type": "some_type",
                },
            },
            "stack_vars": {
                0x10: {
                    "name": "example_name",
                    "type": "some_type",
                },
            },
        }

        return resp

    def function_headers(self):
        resp = {
            0xdeadbeef: {
                "name": str,
                "size": int
            },
        }

        return resp

    def global_vars(self):
        resp = {
            0xdeadbeef: {
                "name": str
            },
        }

        return resp

    def structs(self):
        resp = {
            "example_struct_name": {
                "size": int,
                "example_member_name": {
                    "offset": int,
                    "size": int
                },
            },
        }

        return resp

    def breakpoints(self):
        resp = {
            0xdeadbeef: bool,
            0xdeadbeef+1: bool,
        }

        return resp

    #
    # XMLRPC Server
    #

    def ping(self):
        return True

    def start_xmlrpc_server(self):
        """
        Initialize the XMLRPC thread.
        """
        print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
        server = SimpleXMLRPCServer(
            (HOST, PORT),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        server.register_introspection_functions()
        server.register_function(self.decompile)
        server.register_function(self.function_headers)
        server.register_function(self.function_data)
        server.register_function(self.global_vars)
        server.register_function(self.ping)
        server.register_function(self.structs)
        print("[+] Registered decompilation server!")
        while True:
            server.handle_request()
