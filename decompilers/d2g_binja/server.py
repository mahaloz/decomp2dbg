from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class BinjaDecompilerServer:
    def __init__(self, bv, host=None, port=None):
        self.bv = bv
        self.host = host
        self.port = port

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
            resp["curr_line"] = 0
            return resp

        best_line = min(decomp_lines, key=lambda l: abs(l.address - addr))

        # find the lines location on the decompilation
        for curr_line, il in enumerate(func.hlil.instructions):
            if il == best_line:
                break
        else:
            # if unable to find, put them at start of fun
            curr_line = 0

        resp["curr_line"] = curr_line
        return resp

    def function_data(self, addr: int):
        """
        Returns stack vars and func args

        """
        resp = {
            "args": {},
            "stack_vars": {}
        }

        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return resp

        func = funcs[0]

        # get stack vars
        stack_vars = {}
        for stack_var in func.stack_layout:
            offset = abs(stack_var.storage)
            stack_vars[str(offset)] = {
                "name": stack_var.name,
                "type": str(stack_var.type)
            }

        # get args
        func_args = {}
        for idx, param in enumerate(func.function_type.parameters):
            func_args[str(idx)] = {
                "name": param.name,
                "type": str(param.type)
            }

        resp["args"] = func_args
        resp["stack_vars"] = stack_vars

        return resp


    def function_headers(self):
        resp = {}

        for func in self.bv.functions:

            # Skip everything besides FunctionSymbol
            if func.symbol.type != SymbolType.FunctionSymbol:
                continue

            resp[str(func.start)] = {
                "name": func.name,
                "size": func.total_bytes
            }

        return resp


    def global_vars(self):
        resp = {}
        known_segs = [".data", ".bss"]
        for seg_name in known_segs:
            seg = self.bv.get_section_by_name(seg_name)
            for seg_ea in range(seg.start, seg.end):
                if len(list(self.bv.get_code_refs(seg_ea))) < 1:
                    # no refs
                    continue

                var = self.bv.get_data_var_at(seg_ea)
                resp[str(seg_ea)] = {
                    "name": var.name
                }

        return resp


    def structs(self):
        resp = {}

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
