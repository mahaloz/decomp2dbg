# pylint: disable=missing-class-docstring
import os
import platform
import shutil
from pathlib import Path
import sys
from distutils.util import get_platform
from distutils.command.build import build as st_build

from setuptools import setup
from setuptools.command.develop import develop as st_develop


def _copy_decomp_plugins():
    local_plugins = Path("decompilers").absolute()
    decomp2dbg_loc = Path("decomp2dbg").absolute()
    pip_e_plugins = decomp2dbg_loc.joinpath("decompilers").absolute()

    local_d2d = Path("d2d.py").absolute()

    # clean the install location of symlink or folder
    shutil.rmtree(pip_e_plugins, ignore_errors=True)
    try:
        os.unlink(pip_e_plugins)
        os.unlink(decomp2dbg_loc.joinpath(local_d2d.name))
    except:
        pass

    # first attempt a symlink, if it works, exit early
    try:
        os.symlink(local_plugins, pip_e_plugins, target_is_directory=True)
        os.symlink(local_d2d, decomp2dbg_loc.joinpath(local_d2d.name))
        return
    except:
        pass

    # copy if symlinking is not available on target system
    try:
        shutil.copytree("decompilers", "decomp2dbg/decompilers")
        shutil.copy("d2d.py", "decomp2dbg/d2d.py")
    except:
        pass

class build(st_build):
    def run(self, *args):
        self.execute(_copy_decomp_plugins, (), msg="Copying binsync plugins")
        super().run(*args)

class develop(st_develop):
    def run(self, *args):
        self.execute(_copy_decomp_plugins, (), msg="Linking or copying local plugins folder")
        super().run(*args)


cmdclass = {
    "build": build,
    "develop": develop,
}

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        sys.argv.append('manylinux2014_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(cmdclass=cmdclass)
