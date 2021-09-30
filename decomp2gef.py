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

    DUPLICATION_CHECK = True

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

    def lookup_symbol_from_addr(self, pos: int):
        element = self._get_element(pos)
        if element is None:
            return None

        offset = pos - element.start
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

    def rebase_addr(self, addr):
        vmmap = get_process_maps()
        base_address = min([x.page_start for x in vmmap if x.path == get_filepath()])
        checksec_status = checksec(get_filepath())
        pie = checksec_status["PIE"]  # if pie we will have offset instead of abs address.
        corrected_addr = addr
        if pie:
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
        if cmd == "connect":
            _decompiler_.connect("ida")


register_external_command(DecompilerCommand())


#
# Default GDB overriding for symbol usage
#

class DecompilerBreak(gdb.Command):

    def __init__(self):
        super(DecompilerBreak, self).__init__("break", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print(f"GOT ARG: {arg}")
        gdb.Breakpoint(arg)


DecompilerBreak()