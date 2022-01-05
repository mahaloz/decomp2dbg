from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class DecompilerServer:
    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port

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
