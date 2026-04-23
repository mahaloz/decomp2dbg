#
# decomp2dbg server module
#
# Unified XML-RPC server for decompiler-debugger communication.
#

from decomp2dbg.server.server import LibBSDecompilerServer, DecompilationCache

__all__ = ['LibBSDecompilerServer', 'DecompilationCache', 'start_server']


def start_server(host: str = "localhost", port: int = 3662):
    """
    Start the decomp2dbg XML-RPC server.

    This function auto-detects the current decompiler and starts the server.
    Can be called from any supported decompiler (IDA, Binary Ninja, Ghidra, angr).

    Args:
        host: Host address for XML-RPC server.
        port: Port for XML-RPC server.
    """
    import threading

    server = LibBSDecompilerServer(host=host, port=port)
    t = threading.Thread(target=server.start_xmlrpc_server, daemon=True)
    t.start()
    print(f"[+] decomp2dbg server started on {host}:{port}")
    return server
