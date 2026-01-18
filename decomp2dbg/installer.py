import textwrap
from pathlib import Path

from libbs.plugin_installer import LibBSPluginInstaller, PluginInstaller


class D2dInstaller(LibBSPluginInstaller):
    def __init__(self):
        super().__init__(targets=PluginInstaller.DECOMPILERS + PluginInstaller.DEBUGGERS)
        pkg_files = self.find_pkg_files("decomp2dbg")
        if pkg_files is None:
            raise RuntimeError("Failed to find decomp2dbg package files! Please reinstall or file an issue.")

        self.pkg_path = pkg_files
        self.server_stubs_path = pkg_files / "server" / "stubs"
        self.d2d_server_path = pkg_files / "d2d_server.py"

    def display_prologue(self):
        print(textwrap.dedent("""
        Now installing...
               __                               ___       ____
          ____/ /__  _________  ____ ___  ____ |__ \ ____/ / /_  ____ _
         / __  / _ \/ ___/ __ \/ __ `__ \/ __ \__/ // __  / __ \/ __ `/
        / /_/ /  __/ /__/ /_/ / / / / / / /_/ / __// /_/ / /_/ / /_/ /
        \__,_/\___/\___/\____/_/ /_/ /_/ .___/____/\__,_/_.___/\__, /
                                      /_/                     /____/
        The Decompiler to Debugger Bridge
        """))

    def install_gdb(self, path=None, interactive=True):
        path = super().install_gdb(path=None)
        if path is None:
            return None

        d2d_script_path = self.pkg_path / "d2d_client.py"
        with open(path, "r") as fp:
            init_contents = fp.read()

        write_str = f"source {str(d2d_script_path.absolute())}"
        if write_str in init_contents:
            self.warn("gdbinit already contains d2d source...")
            return None

        with open(path, "a") as fp:
            fp.write(f"\n{write_str}\n")

        return path

    def install_ida(self, path=None, interactive=True):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return None

        # Copy the unified d2d_server.py to IDA plugins
        dst_path = ida_plugin_path / "d2d_server.py"
        self.link_or_copy(self.d2d_server_path, dst_path)
        return dst_path

    def install_angr(self, path=None, interactive=True):
        angr_plugin_path = super().install_angr(path=path)
        if angr_plugin_path is None:
            return None

        # For angr, we create a small wrapper that imports the plugin
        dst_dir = angr_plugin_path / "d2d_angr"
        dst_dir.mkdir(exist_ok=True)

        # Create __init__.py that imports and exposes the plugin
        init_content = '''"""decomp2dbg angr-management plugin."""
from decomp2dbg.d2d_server import start_server

from angrmanagement.plugins import BasePlugin


class Decomp2DbgPlugin(BasePlugin):
    """decomp2dbg plugin for angr-management."""

    def __init__(self, workspace):
        super().__init__(workspace)

    MENU_BUTTONS = ('Configure decomp2dbg...', )

    def handle_click_menu(self, idx):
        if idx == 0:
            start_server()
'''
        init_path = dst_dir / "__init__.py"
        with open(init_path, "w") as f:
            f.write(init_content)

        return dst_dir

    def install_ghidra(self, path=None, interactive=True):
        ghidra_path = super().install_ghidra(path=path)
        if ghidra_path is None:
            return None

        # Copy the unified d2d_server.py to Ghidra scripts
        dst_path = ghidra_path / "d2d_server.py"
        self.link_or_copy(self.d2d_server_path, dst_path)

        print(textwrap.dedent("""
        [*] Ghidra plugin installed!

        IMPORTANT: Ghidra support requires pyhidra.

        To use decomp2dbg with Ghidra:
        1. Install pyhidra: pip install pyhidra
        2. Install pyhidra into Ghidra (see: https://github.com/dod-cyber-crime-center/pyhidra)
        3. In Ghidra, run the 'd2d_server.py' script from the Script Manager
           (or use Tools > decomp2dbg > Start Server)
        4. Connect from GDB: decompiler connect
        """))

        return dst_path

    def install_binja(self, path=None, interactive=True):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        # Create d2d_binja directory
        dst_dir = binja_plugin_path / "d2d_binja"
        dst_dir.mkdir(exist_ok=True)

        # Copy the unified d2d_server.py
        dst_server = dst_dir / "__init__.py"
        # Create a wrapper that imports the plugin
        init_content = '''"""decomp2dbg Binary Ninja plugin."""
from decomp2dbg.d2d_server import create_plugin
create_plugin()
'''
        with open(dst_server, "w") as f:
            f.write(init_content)

        # Copy plugin.json
        src_json = self.server_stubs_path / "plugin.json"
        dst_json = dst_dir / "plugin.json"
        self.link_or_copy(src_json, dst_json)

        return dst_dir
