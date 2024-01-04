import textwrap
from urllib.request import urlretrieve

from libbs.plugin_installer import LibBSPluginInstaller, PluginInstaller


class D2dInstaller(LibBSPluginInstaller):
    def __init__(self):
        super().__init__(targets=PluginInstaller.DECOMPILERS + PluginInstaller.DEBUGGERS)
        pkg_files = self.find_pkg_files("decomp2dbg")
        if pkg_files is None:
            raise RuntimeError("Failed to find decomp2dbg package files! Please reinstall or file an issue.")

        self.plugins_path = pkg_files / "decompilers"

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

        d2d_script_path_pkg = self.plugins_path.parent.joinpath("d2d.py")
        with open(path, "r") as fp:
            init_contents = fp.read()
            
        write_str = f"source {str(d2d_script_path_pkg.absolute())}"
        if write_str in init_contents:
            self.warn("gdbinit already contains d2d source...")
            return None

        with open(path, "a") as fp:
            fp.write(f"\n{write_str}\n")

        return path

    def install_ida(self, path=None, interactive=True):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return

        src_d2d_ida_pkg = self.plugins_path.joinpath("d2d_ida").joinpath("d2d_ida")
        src_d2d_ida_py = self.plugins_path.joinpath("d2d_ida").joinpath("d2d_ida.py")
        dst_d2d_ida_pkg = ida_plugin_path.joinpath("d2d_ida")
        dst_d2d_ida_py = ida_plugin_path.joinpath("d2d_ida.py")
        self.link_or_copy(src_d2d_ida_pkg, dst_d2d_ida_pkg, is_dir=True)
        self.link_or_copy(src_d2d_ida_py, dst_d2d_ida_py)
        return dst_d2d_ida_pkg

    def install_angr(self, path=None, interactive=True):
        angr_plugin_path = super().install_angr(path=path)
        if angr_plugin_path is None:
            return None

        src_d2d_angr_pkg = self.plugins_path.joinpath("d2d_angr")
        dst_d2d_angr_pkg = angr_plugin_path.joinpath("d2d_angr")
        self.link_or_copy(src_d2d_angr_pkg, dst_d2d_angr_pkg, is_dir=True)
        return dst_d2d_angr_pkg

    def install_ghidra(self, path=None, interactive=True):
        ghidra_path = super().install_ghidra(path=path)
        if ghidra_path is None:
            return None

        download_url = "https://github.com/mahaloz/decomp2dbg/releases/latest/download/d2d-ghidra-plugin.zip"
        dst_path = ghidra_path.joinpath("d2d-ghidra-plugin.zip")
        urlretrieve(download_url, dst_path)
        return dst_path

    def install_binja(self, path=None, interactive=True):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("d2d_binja")
        dst_path = binja_plugin_path.joinpath("d2d_binja")
        self.link_or_copy(src_path, dst_path, is_dir=True)
        return dst_path
