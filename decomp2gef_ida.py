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

import ida_hexrays, ida_funcs, idc, ida_pro, ida_lines, idaapi, idautils

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

def _get_all_func_info():
    resp = {"function_headers": {}}
    for f_addr in idautils.Functions():
        if not ((idc.get_func_flags(f_addr) & idc.FUNC_LIB) == idc.FUNC_LIB):
            func_name = ida_funcs.get_func_name(f_addr)
            if not isinstance(func_name, str):
                continue

            if func_name.startswith(".") or "@" in func_name:
                continue

            func_size = ida_funcs.get_func(f_addr).size()
            resp["function_headers"][func_name] = {
                "name": func_name,
                "base_addr": f_addr,
                "size": func_size
            }

    return resp

def _get_all_struct_info():
    resp = {"struct_info": []}
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

@execute_read
def global_info():
    resp = {}
    # function names, addrs, sizes
    resp.update(_get_all_func_info())
    #resp.update(_get_all_struct_info())
    return resp


@execute_read
def decompile(addr: int):
    resp = {"code": None}

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

    # local variable and argument info
    frame = idaapi.get_frame(func_addr)
    frame_size = idc.get_struc_size(frame)
    lvar_info = []
    arg_info = []
    for var in cfunc.lvars:
        if var.name and var.location.in_stack:
            var_info = {}
            var_info["name"] = var.name
            var_info["type"] = var.type().__str__()
            var_info["offset"] = cfunc.mba.stacksize - var.location.stkoff() - idaapi.get_member_size(frame.get_member(frame.memqty - 1))
            lvar_info.append(var_info)

    for arg, idx in zip(cfunc.arguments, cfunc.argidx):
        print(f"ARG: {arg.name} at IDX: {idx}")
        if arg.name:
            arg_i = {}
            arg_i["name"] = arg.name
            arg_i["type"] = arg.type().__str__()
            arg_i["index"] = idx
            arg_info.append(arg_i)

    output = {
        "code": decomp_lines,
        "func_name": func_name,
        "line": cur_line_num,
        "lvars": lvar_info,
        "args": arg_info
    }

    return output

#
# XMLRPC Server Code
#

HOST, PORT = "0.0.0.0", 3662
DEBUG = True


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def ping():
    return True


def start_xmlrpc_server():
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
    server.register_function(decompile)
    server.register_function(global_info)
    server.register_function(ping)
    print("[+] Registered decompilation!")
    while True:
        server.handle_request()

    return


if __name__ == "__main__":
    t = threading.Thread(target=start_xmlrpc_server, args=())
    t.daemon = True
    print("[+] Creating new thread for XMLRPC server: {}".format(t.name))
    t.start()
