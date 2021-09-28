import typing
import xmlrpc.client


#
# Generic Decompiler Interface
#

class Decompiler:
    def __init__(self, name="decompiler", host="127.0.0.1", port=3662):
        self.name = name
        self.host = host
        self.port = port
        self.server = None

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
        return self.server.decompile(addr)

    def get_stack_vars(self, addr, ) -> typing.Dict:
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
        return {}

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
        return {}

    def set_comment(self, cmt, addr, decompilation=False) -> bool:
        """
        Sets a comment in either disassembly or decompilation based on the address.
        Returns whether it was successful or not.
        """
        return False

    def connect(self, name="decompiler", host="127.0.0.1", port=3662) -> bool:
        """
        Connects to the remote decompiler.
        """
        self.name = name
        self.host = host
        self.port = port

        try:
            self.server = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(host, port))
        except ConnectionRefusedError:
            gef_print("[!] Failed to connect")
            return False

        gef_print("[+] Connected!")
        return True


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
            resp = self.decompiler.decompile(pc - 0x0000555555554000)
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

    @only_if_gdb_running
    def do_invoke(self, argv):
        cmd = argv[0]
        if cmd == "connect":
            _decompiler_.connect("ida")


register_external_command(DecompilerCommand())
