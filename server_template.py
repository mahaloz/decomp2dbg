
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

    def global_info(self):
        """
        This function is responsible for returning all global knowledge about the program. Supported
        global knowledge types:
        - function_headers (name, addr, size)
        - global_vars (name, addr, size)
        - structs (name, size, members)

        Each global knowledge type has a specific structure for its associated dict. Every member wrapped with
        a <> is something dynamic that will be defined at runtime, like a function name.
        function_headers:
        {
            <func_name>:
            {
                "name": str,
                "addr": int,
                "size": int
            },
            ...
        }

        global_vars:
        {
            <var_name>:
            {
                "name": str,
                "addr": int,
                "size": int
            },
            ...
        }

        structs:
        {
            <struct_name>:
            {
                "name": str,
                "size": int,
                <struct_member_name>:
                {
                    "name": str,
                    "offset": int,
                    "size": int
                }
                ...
            },
            ...
        }

        Always returns a dict with the defined keys below, which may have None as their values.
        """

        resp = {
            "function_headers": {},
            "global_vars": {},
            "structs": {}
        }

        return resp

    def local_info(self, func_addr: int):
        """
        This function is responsible for returning info about about the current function, usually used with decompile
        interface. Each global knowledge type has a specific structure for its associated dict. Every member
        wrapped with a <> is something dynamic that will be defined at runtime, like a variable name.
        stack_vars:
        {
            <var_name>:
            {
                "name": str,
                "offset: int
            },
        }
        Note: offset is always relative to rbp. Many decompilers will need conversions to match this offset convention
        for stack variables.

        Always returns a dict with the defined keys below, which may have None as their values.
        """
        resp = {
            "func_name": str,
            "stack_vars": {}
        }

        return resp
