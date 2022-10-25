import argparse

from .installer import Decomp2dbgInstaller


def main():
    parser = argparse.ArgumentParser(
        description="""
            The decomp2dbg Command Line Util. 
            """,
        epilog="""
            Examples:
            decomp2dbg --install
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install the decomp2dbg core to supported decompilers as plugins. This option will start an interactive
        prompt asking for install paths for all supported decompilers. Each install path is optional and 
        will be skipped if not path is provided during install. 
        """
    )
    args = parser.parse_args()

    if args.install:
        Decomp2dbgInstaller().install()


if __name__ == "__main__":
    main()
