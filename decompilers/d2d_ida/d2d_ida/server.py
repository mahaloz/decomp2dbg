#
# ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ███████╗███████╗
# ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔══██╗╚════██╗██╔════╝ ██╔════╝██╔════╝
# ██║  ██║█████╗  ██║     ██║   ██║██╔████╔██║██████╔╝ █████╔╝██║  ███╗█████╗  █████╗
# ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔═══╝ ██║   ██║██╔══╝  ██╔══╝
# ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗╚██████╔╝███████╗██║
# ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚══════╝╚═╝
#                                IDA Server
#
# by mahaloz, 2021.
#
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import threading
import functools

import ida_hexrays, ida_funcs, idc, ida_pro, ida_lines, idaapi, idautils, ida_segment


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)
#
# Wrappers for IDA Main thread r/w operations
#
#
# a special note about these functions:
# Any operation that needs to do some type of write to the ida db (idb), needs to be in the main
# thread due to some ida constraints. Sometimes reads also need to be in the main thread.
#


def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)


def execute_sync(func, sync_type):
    """
    Synchronize with the disassembler for safe database access.
    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> object:
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper


def execute_read(func):
    return execute_sync(func, idaapi.MFF_READ)


def execute_write(func):
    return execute_sync(func, idaapi.MFF_WRITE)


def execute_ui(func):
    return execute_sync(func, idaapi.MFF_FAST)


#
# Decompilation API
#

class IDADecompilerServer:
    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port
        self.cache = {
            "global_vars": None,
            "function_headers": None
        }
        self._base_addr = None

        # make the server init cache data once
        self.function_headers()
        self.global_vars()

    def rebase_addr(self, addr, down=False):
        if self._base_addr is None:
            self._base_addr = idaapi.get_imagebase()

        rebased = addr
        if down:
            rebased -= self._base_addr
        elif addr < self._base_addr:
            rebased += self._base_addr

        return rebased


    @execute_read
    def decompile(self, addr):
        addr = self.rebase_addr(addr)
        resp = {
            "decompilation": None,
            "curr_line": None,
            "func_name": None,
        }

        # get the function
        ida_func = ida_funcs.get_func(addr)
        if not ida_func:
            return resp

        func_addr = ida_func.start_ea
        func_name = idc.get_func_name(func_addr)

        # attempt decompilation
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception as e:
            return resp

        # locate decompilation line
        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            # if idaapi failes, try a dirty search!
            up = cfunc.body.find_closest_addr(addr - 0x10)
            if not cfunc.find_item_coords(up, None, y_holder):
                down = cfunc.body.find_closest_addr(addr + 0x10)
                if not cfunc.find_item_coords(down, None, y_holder):
                    return resp

        cur_line_num = y_holder.value()

        # decode ida lines
        enc_lines = cfunc.get_pseudocode()
        decomp_lines = [idaapi.tag_remove(l.line) for l in enc_lines]

        resp["decompilation"] = decomp_lines
        resp["curr_line"] = cur_line_num
        resp["func_name"] = func_name

        return resp

    @execute_read
    def function_data(self, addr):
        addr = self.rebase_addr(addr)
        resp = {
            "stack_vars": None,
            "reg_vars": None
        }

        # get the function
        ida_func = ida_funcs.get_func(addr)
        if not ida_func:
            return resp
        func_addr = ida_func.start_ea

        # attempt decompilation
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception as e:
            return resp

        # get var info
        stack_vars = {}
        reg_vars = {}

        for var in cfunc.lvars:
            if not var.name:
                continue

            # stack variables
            if var.is_stk_var():
                offset = cfunc.mba.stacksize - var.location.stkoff()
                stack_vars[str(offset)] = {
                    "name": var.name,
                    "type": str(var.type())
                }

            # register variables
            elif var.is_reg_var():
                regnum = var.get_reg1()
                reg_name = idaapi.get_mreg_name(regnum, var.width)

                reg_vars[var.name] = {
                    "reg_name": reg_name,
                    "type": str(var.type())
                }
                pass

        resp["stack_vars"] = stack_vars
        resp["reg_vars"] = reg_vars

        return resp

    @execute_read
    def function_headers(self):
        # check if a cache is available
        cache_headers = self.cache["function_headers"]
        if cache_headers:
            return cache_headers

        resp = {}
        # no cache, compute it
        for f_addr in idautils.Functions():
            # assure the function is not a linked library function
            if not ((idc.get_func_flags(f_addr) & idc.FUNC_LIB) == idc.FUNC_LIB):
                func_name = ida_funcs.get_func_name(f_addr)
                if not isinstance(func_name, str):
                    continue

                # double check for .plt or .got names
                if func_name.startswith(".") or "@" in func_name:
                    continue

                func_size = ida_funcs.get_func(f_addr).size()
                resp[str(self.rebase_addr(f_addr, down=True))] = {
                    "name": func_name,
                    "size": func_size
                }

        self.cache["function_headers"] = resp
        return resp

    @execute_read
    def global_vars(self):
        # check if a cache is available
        cache_globals = self.cache["global_vars"]
        if cache_globals:
            return cache_globals

        resp = {}
        known_segs = [".data", ".bss"]
        for seg_name in known_segs:
            seg = idaapi.get_segm_by_name(seg_name)
            if not seg:
                continue

            for seg_ea in range(seg.start_ea, seg.end_ea):
                xrefs = idautils.XrefsTo(seg_ea)
                try:
                    next(xrefs)
                except StopIteration:
                    continue

                name = idaapi.get_name(seg_ea)
                if not name:
                    continue

                resp[str(self.rebase_addr(seg_ea, down=True))] = {
                    "name": name
                }

        self.cache["global_vars"] = resp
        return resp

    @execute_read
    def structs(self):
        resp = {}
        for i in range(idaapi.get_struc_qty()):
            struct_id = idaapi.get_struc_by_idx(i)
            struct = idaapi.get_struc(struct_id)
            struct_info = {
                "name": idaapi.get_struc_name(struct.id),
                "members": []
            }

            for member in struct.members:
                member_info = {
                    "name": idaapi.get_member_name(member.id)
                }

                tif = idaapi.tinfo_t()
                if idaapi.get_member_tinfo(tif, member):
                    member_info["type"] = tif.__str__()
                member_info["size"] = tif.get_size()
                struct_info["members"].append(member_info)

            resp["struct_info"].append(struct_info)
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
