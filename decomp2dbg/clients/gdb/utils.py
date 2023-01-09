import pathlib
from typing import Dict, Optional, Sequence, Union, Any, List, Callable
import subprocess
import os
from functools import lru_cache
import functools
import collections
import re
import tempfile
import hashlib

from elftools.elf.elffile import ELFFile

from ...utils import gef_pystring, warn, err

import gdb

GLOBAL_TMP_DIR = os.path.join(tempfile.gettempdir(), "d2d")
ARCH = None


def identify_arch():
    global ARCH
    if ARCH:
        return ARCH

    with open(get_filepath(), "rb") as fp:
        elf = ELFFile(fp)

    ARCH = elf.get_machine_arch()
    return ARCH


def get_arch_func_args():
    # args taken from GEF
    arch_args = {
        "x64": ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"],
        "x86": [f'$esp+{x}' for x in range(0, 28, 4)],
        "ARM": ["$r0", "$r1", "$r2", "$r3"],
        "SPARC": ["$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 "],
        "MIPS": ["$a0", "$a1", "$a2", "$a3"],
        "RISC-V": ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"]
    }

    arch = identify_arch()
    try:
        args = arch_args[arch]
    except KeyError:
        args = []

    return args


def vmmap_base_addrs():
    addr_maps = {}
    mappings = gdb.execute("info proc mappings", to_string=True).split("\n")
    for mapping in mappings:
        try:
            addr = int(re.findall(r"0x[0-9a-fA-F]+", mapping)[0], 16)
            path = mapping.split(" ")[-1]
        except IndexError:
            continue

        # always use the lowest addr
        if path in addr_maps or path.startswith("["):
            continue

        if addr and path:
            addr_maps[path] = addr

    return addr_maps


def find_text_segment_base_addr(is_remote=False):
    with open(get_filepath(), 'rb') as fp:
        binary_hash = hashlib.md5(fp.read()).hexdigest()

    if is_remote:
        def _should_hash_cmp(path_name):
            return True
    else:
        def _should_hash_cmp(path_name):
            return path_name == get_filepath()

    for path, addr in vmmap_base_addrs().items():
        if _should_hash_cmp(path):
            file = download_file(path) if is_remote else path
            with open(file, 'rb') as fp:
                other_file_hash = hashlib.md5(fp.read()).hexdigest()

            if other_file_hash == binary_hash:
                return addr
    else:
        raise Exception("Unable to find the text segment base addr, please report this!")


@lru_cache()
def is_32bit():
    ptr_size = int(gdb.execute("p sizeof(long long)", to_string=True).split("= ")[1].strip(), 0)
    if ptr_size == 4:
        return True

    return False


def pc():
    try:
        pc_ = int(gdb.execute("print/x $pc",to_string=True).split(" ")[-1], 16)
    except Exception:
        pc_ = None

    return pc_


#
# GEF Clone
#

@lru_cache()
def which(program: str) -> Optional[pathlib.Path]:
    """Locate a command on the filesystem."""
    for path in os.environ["PATH"].split(os.pathsep):
        dirname = pathlib.Path(path)
        fpath = dirname / program
        if os.access(fpath, os.X_OK):
            return fpath

    raise FileNotFoundError(f"Missing file `{program}`")

def exec_external(command: Sequence[str], as_list: bool = False, **kwargs: Any) -> Union[str, List[str]]:
    """Execute an external command and return the result."""
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))
    return [gef_pystring(_) for _ in res.splitlines()] if as_list else gef_pystring(res)

@lru_cache(32)
def checksec(filename: str) -> Dict[str, bool]:
    """Check the security property of the ELF binary. The following properties are:
    - Canary
    - NX
    - PIE
    - Fortify
    - Partial/Full RelRO.
    Return a dict() with the different keys mentioned above, and the boolean
    associated whether the protection was found."""
    readelf = which("readelf")

    def __check_security_property(opt: str, filename: str, pattern: str) -> bool:
        cmd   = [readelf,]
        cmd  += opt.split()
        cmd  += [filename,]
        lines = exec_external(cmd, as_list=True)
        for line in lines:
            if re.search(pattern, line):
                return True
        return False

    results = collections.OrderedDict()
    results["Canary"] = __check_security_property("-rs", filename, r"__stack_chk_fail") is True
    has_gnu_stack = __check_security_property("-W -l", filename, r"GNU_STACK") is True
    if has_gnu_stack:
        results["NX"] = __check_security_property("-W -l", filename, r"GNU_STACK.*RWE") is False
    else:
        results["NX"] = False
    results["PIE"] = __check_security_property("-h", filename, r":.*EXEC") is False
    results["Fortify"] = __check_security_property("-s", filename, r"_chk@GLIBC") is True
    results["Partial RelRO"] = __check_security_property("-l", filename, r"GNU_RELRO") is True
    results["Full RelRO"] = results["Partial RelRO"] and __check_security_property("-d", filename, r"BIND_NOW") is True
    return results



@lru_cache()
def is_remote_debug() -> bool:
    """"Return True is the current debugging session is running through GDB remote session."""
    return "remote" in gdb.execute("maintenance print target-stack", to_string=True)


def pid() -> int:
    """Return the PID of the target process."""
    pid_ = gdb.selected_inferior().pid
    if not pid_:
        pid_ = gdb.selected_thread().ptid[1]
        if not pid_:
            raise RuntimeError("cannot retrieve PID for target process")

    return pid_



@lru_cache()
def get_filepath() -> Optional[str]:
    """Return the local absolute path of the file currently debugged."""
    filename = gdb.current_progspace().filename

    if is_remote_debug():
        # if no filename specified, try downloading target from /proc
        if filename is None:
            pid_ = pid()
            if pid_ > 0:
                return download_file(f"/proc/{pid_:d}/exe", use_cache=True)
            return None

        # if target is remote file, download
        elif filename.startswith("target:"):
            fname = filename[len("target:") :]
            return download_file(fname, use_cache=True, local_name=fname)

        elif filename.startswith(".gnu_debugdata for target:"):
            fname = filename[len(".gnu_debugdata for target:") :]
            return download_file(fname, use_cache=True, local_name=fname)

        return filename
    else:
        if filename is not None:
            return filename
        # inferior probably did not have name, extract cmdline from info proc
        return get_path_from_info_proc()


def get_path_from_info_proc() -> Optional[str]:
    for x in gdb.execute("info proc", to_string=True).splitlines():
        if x.startswith("exe = "):
            return x.split(" = ")[1].replace("'", "")
    return None


def download_file(remote_path: str, use_cache: bool = False, local_name: Optional[str] = None) -> Optional[str]:
    """Download filename `remote_path` inside the mirror tree inside the `gef.config["gef.tempdir"]`.
    The tree architecture must be `gef.config["gef.tempdir"]/gef/<local_pid>/<remote_filepath>`.
    This allow a "chroot-like" tree format."""

    local_root = pathlib.Path(GLOBAL_TMP_DIR) / str(pid())
    if local_name is None:
        local_path = local_root / remote_path.strip(os.sep)
    else:
        local_path = local_root / local_name.strip(os.sep)

    if use_cache and local_path.exists():
        return str(local_path.absolute())

    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        gdb.execute(f"remote get {remote_path} {local_path.absolute()}")
        local_path = str(local_path.absolute())
    except gdb.error:
        # fallback memory view
        with open(local_path, "w") as f:
            if is_32bit():
                f.write(f"00000000-ffffffff rwxp 00000000 00:00 0                    {get_filepath()}\n")
            else:
                f.write(f"0000000000000000-ffffffffffffffff rwxp 00000000 00:00 0                    {get_filepath()}\n")

    except Exception as e:
        err(f"download_file() failed: {e}")
        local_path = None

    return local_path


def is_alive() -> bool:
    """Check if GDB is running."""
    try:
        return gdb.selected_inferior().pid > 0
    except Exception:
        return False


def only_if_gdb_running(f: Callable) -> Callable:
    """Decorator wrapper to check if GDB is running."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")

    return wrapper

