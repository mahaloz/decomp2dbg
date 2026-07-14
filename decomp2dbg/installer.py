import shutil
import textwrap
from pathlib import Path

from declib.plugin_installer import DecLibPluginInstaller, PluginInstaller


class D2dInstaller(DecLibPluginInstaller):
    def __init__(self):
        super().__init__(targets=PluginInstaller.DECOMPILERS + PluginInstaller.DEBUGGERS)
        pkg_files = self.find_pkg_files("decomp2dbg")
        if pkg_files is None:
            raise RuntimeError("Failed to find decomp2dbg package files! Please reinstall or file an issue.")

        self.pkg_path = pkg_files
        self.stub_files = pkg_files / "server" / "stubs"

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

    def _copy_plugin_to_path(self, path):
        """Copy the d2d_server.py plugin file to the given path."""
        src = self.pkg_path / "d2d_server.py"
        dst = Path(path) / src.name
        self.link_or_copy(src, dst, symlink=True)

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
        path = super().install_ida(path=path, interactive=interactive)
        if not path:
            return None

        self._copy_plugin_to_path(path)
        return path

    def install_ghidra(self, path=None, interactive=True):
        path = super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return None

        self._copy_plugin_to_path(path)
        return path

    def install_binja(self, path=None, interactive=True):
        path = super().install_binja(path=path, interactive=interactive)
        if not path:
            return None

        # Binja requires a folder for the plugin
        d2d_binja_dir = path / "d2d_binja"
        if d2d_binja_dir.exists():
            shutil.rmtree(d2d_binja_dir)
        d2d_binja_dir.mkdir()

        # Copy things to the new folder
        self.link_or_copy(self.stub_files / "__init__.py", d2d_binja_dir / "__init__.py", symlink=True)
        self.link_or_copy(self.stub_files / "plugin.json", d2d_binja_dir / "plugin.json")
        return path

    def install_angr(self, path=None, interactive=True):
        path = super().install_angr(path=path, interactive=interactive)
        if not path:
            return None

        # angr requires a folder for the plugin
        d2d_angr_dir = path / "d2d_angr"
        if d2d_angr_dir.exists():
            shutil.rmtree(d2d_angr_dir)
        d2d_angr_dir.mkdir()

        # Copy things to the new folder
        self.link_or_copy(self.stub_files / "__init__.py", d2d_angr_dir / "__init__.py", symlink=True)
        return path
