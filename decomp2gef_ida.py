"""
Inspired by @hugsy's ida_interact.py
"""

from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import threading
import functools

import ida_hexrays, ida_funcs, idc, ida_pro, ida_lines, idaapi

#
#   Wrappers for IDA Main thread r/w operations
#

# a special note about these functions:
# Any operation that needs to do some type of write to the ida db (idb), needs to be in the main thread due to
# some ida constraints. Sometimes reads also need to be in the main thread. To make things efficient, most heavy
# things are done in the controller and just setters and getters are done here.


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
# RPCXML Server Code
#

HOST, PORT = "0.0.0.0", 3662
DEBUG = True


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


@execute_read
def decompile(addr: int):
    resp = {"code": None}

    # get the function
    ida_func = ida_funcs.get_func(addr)
    if not ida_func:
        print("FAILED TO GET FUNCTION")
        return resp

    func_addr = ida_func.start_ea
    func_name = idc.get_func_name(func_addr)

    # attempt decompilation
    try:
        cfunc = ida_hexrays.decompile(func_addr)
    except Exception as e:
        print("FAILED TO GET DECOMPILATION")
        return resp

    # locate decompilation line
    item = cfunc.body.find_closest_addr(addr)
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        print("FAILED TO GET LINE")
        return resp
    cur_line_num = y_holder.value()

    # decode ida lines
    enc_lines = cfunc.get_pseudocode()
    decomp_lines = [idaapi.tag_remove(l.line) for l in enc_lines]

    #enc_addr_decomp = cfunc.eamap[addr][0].print1(None)
    #ascii_str = ida_lines.tag_remove(enc_addr_decomp)
    #ida_pro.str2user(enc_addr_decomp)

    #print(f"[+] Got Decompilation: {decomp[:15]}")
    #print(f"[+] Got Decomp Lines: {decomp_lines[0]}")
    #print(f"[+] Got Current line: {ascii_str}")
    #print(f"[+] Starting Search...")

    #for cur_line_num in range(len(decomp_lines)):
    #    if ascii_str in decomp_lines[cur_line_num]:
    #        print(f"[+] Break {cur_line_num}...")
    #        break
    #else:
    #    print("FAILED TO FIND DECOMP LINE")
    #    return resp

    return {
        "code": decomp_lines,
        "func_name": func_name,
        "line": cur_line_num
    }


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread.
    """
    print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
    server = SimpleXMLRPCServer((HOST, PORT),
                                requestHandler=RequestHandler,
                                logRequests=False,
                                allow_none=True)
    server.register_introspection_functions()
    server.register_function(decompile)
    print("[+] Registered decompilation!")
    while True:
        server.handle_request()

    return


if __name__ == "__main__":
    t = threading.Thread(target=start_xmlrpc_server, args=())
    t.daemon = True
    print("[+] Creating new thread for XMLRPC server: {}".format(t.name))
    t.start()
