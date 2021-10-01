import typing
import xmlrpc.client
import functools
import sortedcontainers

#
# Helper Classes
#


class SymbolMapElement:

    __slots__ = ('start', 'length', 'sym')

    def __init__(self, start, length, sym):
        self.start: int = start
        self.length: int = length
        self.sym = sym

    def __contains__(self, offset):
        return self.start <= offset < self.start + self.length

    def __repr__(self):
        return "<%d-%d: %s>" % (self.start, self.start + self.length, self.sym)


class SymbolMap:
    """
    A binary search dict implementation for ranges. Symbols will map for a range and we need to
    be able to lookup addresses in the middle of the range fast
    """

    __slots__ = ('_symmap', '_sym_to_addr_tbl')

    DUPLICATION_CHECK = False

    def __init__(self):
        self._symmap = sortedcontainers.SortedDict()
        self._sym_to_addr_tbl = {}

    def items(self):
        return self._symmap.items()

    def add_mapping(self, start_pos, length, sym):
        # duplication check
        if self.DUPLICATION_CHECK:
            try:
                pre = next(self._symmap.irange(maximum=start_pos, reverse=True))
                if start_pos in self._symmap[pre]:
                    raise ValueError("New mapping is overlapping with an existing element.")
            except StopIteration:
                pass

        self._sym_to_addr_tbl[sym] = start_pos
        self._symmap[start_pos] = SymbolMapElement(start_pos, length, sym)

    def rename_symbol(self, symbol: str):
        sym_addr = self.lookup_addr_from_symbol(symbol)
        if not sym_addr:
            return False

        element = self._get_element(sym_addr)
        element.sym = sym_addr
        self._sym_to_addr_tbl[symbol] = sym_addr
        return True

    def lookup_addr_from_symbol(self, symbol: str):
        try:
            addr = self._sym_to_addr_tbl[symbol]
        except KeyError:
            return None

        return addr

    def lookup_symbol_from_addr(self, addr: int):
        element = self._get_element(addr)
        if element is None:
            return None

        offset = addr - element.start
        return element.sym, offset

    def _get_element(self, pos: int) -> typing.Optional[SymbolMapElement]:
        try:
            pre = next(self._symmap.irange(maximum=pos, reverse=True))
        except StopIteration:
            return None

        element = self._symmap[pre]
        if pos in element:
            return element
        return None


_decomp_sym_tab_ = SymbolMap()

#
# Decorators
#

# decompiler decorators
def only_if_decompiler_connected(f):
    """Decorator wrapper to check if Decompiler is online."""

    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if self.connected():
            return f(self, *args, **kwargs)

    return wrapper


#
# Generic Decompiler Interface
#

class Decompiler:
    def __init__(self, name="decompiler", host="127.0.0.1", port=3662):
        self.name = name
        self.host = host
        self.port = port
        self.server = None

    #
    # Server Operations
    #

    def connected(self):
        return True if self.server else False

    def connect(self, name="decompiler", host="127.0.0.1", port=3662) -> bool:
        """
        Connects to the remote decompiler.
        """
        self.name = name
        self.host = host
        self.port = port

        try:
            self.server = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(host, port))
            self.server.ping()
        except (ConnectionRefusedError, AttributeError) as e:
            gef_print("[!] Failed to connect")
            self.server = None
            return False

        gef_print("[+] Connected!")
        return True

    @only_if_decompiler_connected
    def disconnect(self):
        self.server.disconnect()
        self.server = None

    #
    # Decompilation Operations
    #

    def global_info(self):
        """
        Will get the global information associated with the decompiler. Things like:
        - [X] function headers
        - [ ] structs
        - [ ] enums

        Return format:
        {
            "function_headers":
            {
                "<some_func_name>":
                {
                    "name": str
                    "base_addr": int
                    "size": int
                }
            }
        }
        """
        return self.server.global_info()

    @only_if_decompiler_connected
    def decompile(self, addr) -> typing.Dict:
        """
        Decompiles an address that may be in a function boundary. Returns a dict like the following:
        {
            "code": Optional[List[str]],
            "func_name": str,
            "line": int
        }

        Code should be the full decompilation of the function the address is within. If not in a function, None is
        also acceptable.
        """
        return self.server.decompile(self.rebase_addr(addr))

    @only_if_decompiler_connected
    def get_stack_vars(self, addr) -> typing.Dict:
        """
        Gets all the stack vars associated with the function addr is in. If addr is not in a function, will return None
        for the function addr. Returns a dict like the following:
        {
            "func_addr": Optional[str],
            "members":
            [
                {
                    "offset": int,
                    "name": str,
                    "size": int,
                    "type": str
                }
            ]
        }

        All offsets will be negative offsets of the base pointer.
        """
        return self.server.get_stack_vars(self.rebase_addr(addr))

    @only_if_decompiler_connected
    def get_structs(self) -> typing.List[typing.Dict]:
        """
        Gets all the structs defined by the decompiler or user. Returns a dict like the following:
        [
            {
                "struct_name": str,
                "size": int,
                "members":
                [
                    {
                        "offset": int,
                        "name": str,
                        "size": int,
                        "type": str
                    }
                ]
            }
            ...
        ]
        """
        return self.server.get_structs()

    @only_if_decompiler_connected
    def set_comment(self, cmt, addr, decompilation=False) -> bool:
        """
        Sets a comment in either disassembly or decompilation based on the address.
        Returns whether it was successful or not.
        """
        return self.server.set_comment(cmt, self.rebase_addr(addr), decompilation)

    #
    # Decompiler Utils
    #

    def rebase_addr(self, addr, up=False):
        vmmap = get_process_maps()
        base_address = min([x.page_start for x in vmmap if x.path == get_filepath()])
        checksec_status = checksec(get_filepath())
        pie = checksec_status["PIE"]  # if pie we will have offset instead of abs address.
        corrected_addr = addr
        if pie:
            if up:
                corrected_addr += base_address
            else:
                corrected_addr -= base_address

        return corrected_addr

    def lookup_symbol_from_name(self, name: str) -> int:
        return 0

    def lookup_symbol_from_addr(self, addr: int) -> (str, int):

        return "", 0



_decompiler_ = Decompiler()


#
# GEF Context Pane for Decompiler
#

class DecompilerCTXPane:
    def __init__(self, decompiler):
        self.decompiler = decompiler

        self.ready_to_display = False
        self.decomp_lines = []
        self.curr_line = -1
        self.curr_func = ""

    def _decompile_cur_pc(self, pc):
        try:
            resp = self.decompiler.decompile(pc)
        except Exception as e:
            gef_print("[!] DECOMPILER ERROR")
            gef_print(e)
            return False

        code = resp['code']
        if not code:
            return False

        self.decomp_lines = code
        self.curr_func = resp["func_name"]
        self.curr_line = resp["line"]

        return True

    def display_pane(self):
        """
        Display the current decompilation, with an arrow next to the current line.
        """
        if not self.decompiler.connected():
            return

        if not self.ready_to_display:
            gef_print("Unable to decompile function")
            return

        # configure based on source config
        past_lines_color = get_gef_setting("theme.old_context")
        nb_lines = get_gef_setting("context.nb_lines_code")
        cur_line_color = get_gef_setting("theme.source_current_line")

        # use GEF source printing method
        for i in range(self.curr_line - nb_lines + 1, self.curr_line + nb_lines):
            if i < 0:
                continue

            if i < self.curr_line:
                gef_print(
                    "{}".format(Color.colorify("  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], ), past_lines_color))
                )

            if i == self.curr_line:
                prefix = "{}{:4d}\t ".format(RIGHT_ARROW[1:], i + 1)
                gef_print(Color.colorify("{}{:s}".format(prefix, self.decomp_lines[i]), cur_line_color))

            if i > self.curr_line:
                try:
                    gef_print("  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], ))
                except IndexError:
                    break
        return

    def title(self):
        """
        Special note: this function is always called before display_pane
        """
        if not self.decompiler.connected():
            return None

        self.ready_to_display = self._decompile_cur_pc(current_arch.pc)

        if self.ready_to_display:
            title = "decompiler:{:s}:{:s}:{:d}".format(self.decompiler.name, self.curr_func, self.curr_line)
        else:
            title = "decomipler:{:s}:error".format(self.decompiler.name)

        return title


_decompiler_ctx_pane_ = DecompilerCTXPane(_decompiler_)
register_external_context_pane("decompilation", _decompiler_ctx_pane_.display_pane, _decompiler_ctx_pane_.title)


#
# GEF Command Interface for Decompiler
#

class DecompilerCommand(GenericCommand):
    """The command interface for the remote Decompiler"""
    _cmdline_ = "decompiler"
    _syntax_ = "{:s} [connect | disconnect]".format(_cmdline_)

    def do_invoke(self, argv):
        cmd = argv[0]
        args = argv[1:]
        self._handle_cmd(cmd, args)

    #
    # Decompiler command handlers
    #

    def _handle_cmd(self, cmd, args):
        handler_str = "_handle_{}".format(cmd)
        if hasattr(self, handler_str):
            handler = getattr(self, handler_str)
            handler(args)
        else:
            self._handler_failed("command does not exist")

    def _handle_connect(self, args):
        if len(args) != 1:
            self._handler_failed("not enough args")
            return

        _decompiler_.connect(name=args[0])

    def _handle_global_info(self, args):
        if len(args) != 1:
            self._handler_failed("not enough args")

        op = args[0]

        # import global info
        if op == "import":
            resp = _decompiler_.global_info()
            funcs_info = resp['function_headers']
            funcs_to_add = []
            for func_addr in funcs_info:
                func_i = funcs_info[func_addr]
                _decomp_sym_tab_.add_mapping(
                    func_i["base_addr"],
                    func_i["size"],
                    func_i["name"]
                )
                funcs_to_add.append((func_i["name"],  func_i["base_addr"], None))

            self.add_ida_symbol(funcs_to_add)
            return

        if op == "status":
            gef_print("======= Decompiler Symbol Info =======")
            gef_print("Imported {:d} symbols".format(len(_decomp_sym_tab_._sym_to_addr_tbl)))
            for sym, addr in _decomp_sym_tab_._sym_to_addr_tbl.items():
                gef_print("{:s}@0x{:x}".format(sym, addr))
            gef_print("======= END Decompiler Symbol Info =======")

    def _handler_failed(self, error):
        gef_print("[!] Failed to handle decompiler command: {}.".format(error))

    #
    # Decompiler debug info setters
    #

    def add_ida_symbol(self, function_info):
        try:
            gcc = which("gcc")
            objcopy = which("objcopy")
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        cache = {}

        def create_blank_elf(text_base):
            if cache:
                open(cache["fname"], "wb").write(cache["data"])
                return cache["fname"]
            # create light ELF
            fd, fname = tempfile.mkstemp(dir="/tmp", suffix=".c")
            os.fdopen(fd, "w").write("int main() {}")
            os.system(f"{gcc} {fname} -no-pie -o {fname}.debug")
            os.unlink(f"{fname}")
            # delete unneeded section for faster
            os.system(f"{objcopy} --only-keep-debug {fname}.debug")
            os.system(f"{objcopy} --strip-all {fname}.debug")
            elf = get_elf_headers(f"{fname}.debug")
            for s in elf.shdrs:
                section_name = s.sh_name
                if section_name == ".text":  # .text is needed, don't remove
                    continue
                if section_name == ".interp":  # broken if removed
                    continue
                if section_name == ".rela.dyn":  # cannot removed
                    continue
                if section_name == ".dynamic":  # cannot removed
                    continue
                os.system(f"{objcopy} --remove-section={section_name} {fname}.debug 2>/dev/null")
            cache["fname"] = fname + ".debug"
            cache["data"] = open(cache["fname"], "rb").read()
            return cache["fname"]

        def apply_symbol(fname, cmd_string_arr, text_base):
            cmd_string = ' '.join(cmd_string_arr)
            os.system(f"{objcopy} {cmd_string} {fname}")
            gdb.execute(f"add-symbol-file {fname} {text_base:#x}", to_string=True)
            os.unlink(fname)
            return

        info("{:d} entries will be added".format(len(function_info)))

        vmmap = get_process_maps()
        text_base = min([x.page_start for x in vmmap if x.path == get_filepath()])

        cmd_string_arr = []
        fname = create_blank_elf(text_base)
        for i, (fn, fa, typ) in enumerate(function_info):
            # debug print
            if i > 1 and i % 10000 == 0:
                info("{:d} entries were processed".format(i))

            if typ in ["T", "t", "W", None]:
                type_flag = "function"
            else:
                type_flag = "object"
            if typ and typ in "abcdefghijklmnopqrstuvwxyz":
                global_flag = "local"
            else:
                global_flag = "global"

            if fa > text_base:
                cmd_string_arr.append(
                    f"--add-symbol '{fn}'={fa:#x},{global_flag},{type_flag}")  # lower address needs not relative, use absolute
            else:
                relative_addr = fa #- text_base
                cmd_string_arr.append(
                    f"--add-symbol '{fn}'=.text:{relative_addr:#x},{global_flag},{type_flag}")  # higher address needs relative

            if i > 1 and i % 1000 == 0:
                # too long, so let's commit
                apply_symbol(fname, cmd_string_arr, text_base)
                # re-init
                fname = create_blank_elf(text_base)
                cmd_string_arr = []

        # commit remain
        if cmd_string_arr:
            apply_symbol(fname, cmd_string_arr, text_base)

        info("{:d} entries were processed".format(i + 1))
        return

register_external_command(DecompilerCommand())

#
# Dirty overrides
#

@lru_cache(maxsize=512)
def gdb_get_location_from_symbol(address):
    """Retrieve the location of the `address` argument from the symbol table.
    Return a tuple with the name and offset if found, None otherwise."""
    # this is horrible, ugly hack and shitty perf...
    # find a *clean* way to get gdb.Location from an address
    name = None
    sym = gdb.execute("info symbol {:#x}".format(address), to_string=True)
    if sym.startswith("No symbol matches"):
        # --- start patch --- #
        sym_obj = _decomp_sym_tab_.lookup_symbol_from_addr(_decompiler_.rebase_addr(address))
        return sym_obj
        # --- end patch --- #

    i = sym.find(" in section ")
    sym = sym[:i].split()
    name, offset = sym[0], 0
    if len(sym) == 3 and sym[2].isdigit():
        offset = int(sym[2])
    return name, offset