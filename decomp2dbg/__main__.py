import argparse
import tempfile

from .installer import D2dInstaller


SUPPORTED_DECOMPILERS = ("ghidra", "ida", "binja", "angr")


def _run_server(binary_path: str, decompiler: str, host: str, port: int):
    """Start a headless decompiler server for the given binary."""
    from declib.api import DecompilerInterface
    from declib.decompilers import GHIDRA_DECOMPILER, IDA_DECOMPILER, BINJA_DECOMPILER, ANGR_DECOMPILER

    from decomp2dbg.server import DecLibDecompilerServer

    decompiler_map = {
        "ghidra": GHIDRA_DECOMPILER,
        "ida": IDA_DECOMPILER,
        "binja": BINJA_DECOMPILER,
        "angr": ANGR_DECOMPILER,
    }

    force_decompiler = decompiler_map[decompiler]
    tmpdir = tempfile.mkdtemp(prefix="d2d_server_")

    print(f"[*] Starting headless {decompiler} server for {binary_path} on {host}:{port}...")
    deci = DecompilerInterface.discover(
        force_decompiler=force_decompiler,
        headless=True,
        binary_path=binary_path,
        project_location=tmpdir,
        project_name="d2d_server",
    )

    server = DecLibDecompilerServer(deci=deci, host=host, port=port)
    try:
        server.start_xmlrpc_server()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
    finally:
        deci.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="""
            The decomp2dbg Command Line Util.
            """,
        epilog="""
            Examples:
            decomp2dbg --install
            decomp2dbg --server ./path/to/binary -d ghidra --port 3662
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install the decomp2dbg core to supported decompilers as plugins. This option will start an interactive
        prompt asking for install paths for all supported decompilers. Each install path is optional and
        will be skipped if not path is provided during install.
        """
    )
    parser.add_argument(
        "--server", metavar="BINARY", help="""
        Start a headless decompiler XML-RPC server for the given binary.
        The server will run in the foreground until interrupted (Ctrl+C).
        """
    )
    parser.add_argument(
        "-d", "--decompiler", choices=SUPPORTED_DECOMPILERS, default="ghidra",
        help="Decompiler backend to use with --server (default: ghidra)."
    )
    parser.add_argument(
        "--host", default="localhost",
        help="Host address for the server (default: localhost)."
    )
    parser.add_argument(
        "--port", type=int, default=3662,
        help="Port for the server (default: 3662)."
    )
    args = parser.parse_args()

    if args.install:
        D2dInstaller().install()
    elif args.server:
        _run_server(args.server, args.decompiler, args.host, args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
