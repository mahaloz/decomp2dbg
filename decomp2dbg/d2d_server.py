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


def _ask_and_start_server(*args, deci=None, **kwargs):
    """Menu action callback: ask user for host:port and start the server."""
    result = deci.gui_ask_for_string(
        "Host and port to start server on (default: localhost:3662)",
        title="Starting decomp2dbg server",
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


def create_plugin(*args, **kwargs):
    """Plugin entry point for all decompilers."""
    from libbs.api import DecompilerInterface

    deci = DecompilerInterface.discover(
        plugin_name="decomp2dbg",
        init_plugin=True,
        gui_init_args=args,
        gui_init_kwargs=kwargs,
    )

    deci.gui_register_ctx_menu(
        "Startdecomp2dbgServer",
        "Start decomp2dbg server",
        _ask_and_start_server,
        category="decomp2dbg",
    )

    return deci.gui_plugin


# =============================================================================
# LibBS generic plugin loader
# =============================================================================

import sys

if sys.version[0] == "2":
    import subprocess
    from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer

    GhidraBridgeServer.run_server(background=True)
    process = subprocess.Popen("decomp2dbg --run".split(" "))
    if process.poll() is not None:
        raise RuntimeError(
            "Failed to run the Python3 backend. It's likely Python3 (and its scripts) is not in your Path inside Ghidra."
        )
else:
    try:
        import idaapi
        has_ida = True
    except ImportError:
        has_ida = False
    try:
        import angrmanagement
        has_angr = True
    except ImportError:
        has_angr = False

    if not has_ida and not has_angr:
        create_plugin()
    elif has_angr:
        from angrmanagement.plugins import BasePlugin

        class AngrBSPluginThunk(BasePlugin):
            def __init__(self, workspace):
                super().__init__(workspace)
                globals()["workspace"] = workspace
                self.plugin = create_plugin()

            def teardown(self):
                pass


def PLUGIN_ENTRY(*args, **kwargs):
    """IDA plugin entry point."""
    return create_plugin(*args, **kwargs)
