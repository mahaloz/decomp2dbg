# discover interface
is_gdb = True
try:
    import gdb
except ImportError:
    is_gdb = False

if is_gdb:
    global_vars = globals()
    if "gef" in global_vars:
        from decomp2dbg.clients.gdb.gef_client import GEFClient
        GEFClient(register_external_context_pane, gef_print)
    elif "pwndbg" in global_vars:
        from decomp2dbg.clients.gdb.pwndbg_client import PwndbgClient
        PwndbgClient()
    elif "peda" in global_vars:
        pass
    else:
        from decomp2dbg.clients.gdb.gdb_client import GDBClient
        GDBClient()
else:
    raise Exception("Unsupported debugger type detected, decomp2dbg will not run!")