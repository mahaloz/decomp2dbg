import textwrap
from urllib.request import urlretrieve

import pkg_resources
from pathlib import Path

from binsync.installer import Installer

class Decomp2dbgInstaller(Installer):
    def __init__(self):
        super(Decomp2dbgInstaller, self).__init__(targets=Installer.DECOMPILERS + ('gdb',))
        self.plugins_path = Path(
            pkg_resources.resource_filename("decomp2dbg", f"decompilers")
        )
    
    def display_prologue(self):
        print(textwrap.dedent("""
               __                               ___       ____         
          ____/ /__  _________  ____ ___  ____ |__ \ ____/ / /_  ____ _
         / __  / _ \/ ___/ __ \/ __ `__ \/ __ \__/ // __  / __ \/ __ `/
        / /_/ /  __/ /__/ /_/ / / / / / / /_/ / __// /_/ / /_/ / /_/ / 
        \__,_/\___/\___/\____/_/ /_/ /_/ .___/____/\__,_/_.___/\__, /  
                                      /_/                     /____/   
        Now installing decomp2dbg...
        Please input decompiler/debugger install paths as prompted. Enter nothing to either use
        the default install path if one exist, or to skip.
        """))
    
    def install_gdb(self, path=None):
        default_gdb_path = Path("~/").joinpath(".gdbinit").expanduser()
        default_str = f" [default = {default_gdb_path}]"
        path = self.ask_path(f"gdbinit path{default_str}:\n") if path is None else path
        if not path:
            if not default_gdb_path:
                return None

            path = default_gdb_path

        d2d_script_path_pkg = self.plugins_path.parent.joinpath("d2d.py")
        with open(path, "r") as fp:
            init_contents = fp.read()
            
        write_str = f"source {str(d2d_script_path_pkg.absolute())}"
        if write_str in init_contents:
            return None

        with open(path, "a") as fp:
            fp.write(f"\n{write_str}\n")

    def install_ida(self, path=None):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return

        src_d2d_ida_pkg = self.plugins_path.joinpath("ida_binsync").joinpath("ida_binsync")
        src_d2d_ida_py = self.plugins_path.joinpath("ida_binsync").joinpath("ida_binsync.py")
        dst_d2d_ida_pkg = ida_plugin_path.joinpath("ida_binsync")
        dst_d2d_ida_py = ida_plugin_path.joinpath("ida_binsync.py")
        self.link_or_copy(src_d2d_ida_pkg, dst_d2d_ida_pkg, is_dir=True)
        self.link_or_copy(src_d2d_ida_py, dst_d2d_ida_py)

    def install_angr(self, path=None):
        angr_plugin_path = super().install_angr(path=path)
        if angr_plugin_path is None:
            return None

        src_d2d_angr_pkg = self.plugins_path.joinpath("angr_binsync")
        dst_d2d_angr_pkg = angr_plugin_path.joinpath("angr_binsync")
        self.link_or_copy(src_d2d_angr_pkg, dst_d2d_angr_pkg, is_dir=True)

    def install_ghidra(self, path=None):
        ghidra_path = super().install_ghidra(path=path)
        if ghidra_path is None:
            return None

        download_url = "https://github.com/mahaloz/decomp2dbg/releases/latest/download/d2d-ghidra-plugin.zip"
        dst_path = ghidra_path.joinpath("d2d-ghidra-plugin.zip")
        urlretrieve(download_url, dst_path)

    def install_binja(self, path=None):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("d2d_binja")
        dst_path = binja_plugin_path.joinpath("d2d_binja")
        self.link_or_copy(src_path, dst_path, is_dir=True)
