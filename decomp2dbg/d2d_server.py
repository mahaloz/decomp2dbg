# decomp2dbg - Decompiler to Debugger Bridge
# @author mahaloz
# @category decomp2dbg
# @menupath Tools.decomp2dbg.Start Server
# @runtime PyGhidra

"""
Unified decomp2dbg server entry point.

This file can be:
1. Copied to IDA's plugins folder as d2d_server.py
2. Copied to Binary Ninja's plugins folder as d2d_server.py
3. Run as a Ghidra script via pyhidra
4. Loaded in angr-management

The script auto-detects which decompiler it's running in and starts
the XML-RPC server appropriately.
"""

import threading

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 3662


def start_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """Start the decomp2dbg XML-RPC server."""
    from decomp2dbg.server import LibBSDecompilerServer

    server = LibBSDecompilerServer(host=host, port=port)
    t = threading.Thread(target=server.start_xmlrpc_server, daemon=True)
    t.start()
    print(f"[+] decomp2dbg server started on {host}:{port}")
    print("[+] Connect from GDB with: decompiler connect")
    return server


def create_plugin(*args, **kwargs):
    """Plugin entry point for decompilers."""
    from libbs.api import DecompilerInterface

    deci = DecompilerInterface.discover()

    # Ask user for host:port
    result = deci.gui_ask_for_string(
        "Host and port to start server on",
        title="Starting decomp2dbg server",
        default_answer="localhost:3662"
    )

    if not result:
        return None

    # Parse host:port
    try:
        if ":" in result:
            host, port_str = result.rsplit(":", 1)
            port = int(port_str)
        else:
            host = result
            port = DEFAULT_PORT
    except ValueError:
        print(f"[!] Invalid port in '{result}', using default")
        host = DEFAULT_HOST
        port = DEFAULT_PORT

    start_server(host=host, port=port)
    return deci


def PLUGIN_ENTRY(*args, **kwargs):
    """IDA plugin entry point."""
    return create_plugin(*args, **kwargs)


# Auto-run for non-IDA decompilers
try:
    import idaapi
    HAS_IDA = True
except ImportError:
    HAS_IDA = False

if not HAS_IDA:
    create_plugin()
