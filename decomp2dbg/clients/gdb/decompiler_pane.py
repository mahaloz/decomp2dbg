from ...utils import *
from .utils import pc


class DecompilerPane:
    def __init__(self, decompiler, printer=pprint):
        self.decompiler: "GDBDecompilerClient" = decompiler

        self.ready_to_display = False
        self.decomp_lines = []
        self.curr_line = -1
        self.curr_func = ""
        self.print = printer

        # XXX: this needs to be removed in the future
        self.stop_global_import = False

    def update_event(self, pc_):
        if (self.decompiler.gdb_client.base_addr_end is not None) and \
                (self.decompiler.gdb_client.base_addr_start is not None):
            if pc_ > self.decompiler.gdb_client.base_addr_end or pc_ < self.decompiler.gdb_client.base_addr_start:
                return False

        
        rebased_pc = self.decompiler.rebase_addr(pc_)

        # update all known function names
        self.decompiler.update_symbols()

        # decompile the current pc location
        try:
            resp = self.decompiler.decompile(rebased_pc)
        except Exception as e:
            warn(f"Decompiler failed to get a response from decompiler on "
                 f"{hex(rebased_pc) if isinstance(rebased_pc,int) else rebased_pc} with: {e}")
            return False

        # set the decompilation for next use in display_pane
        decompilation = resp['decompilation']
        if not decompilation:
            warn("Decompiler server sent back a response without decompilation lines for "
                 f"{hex(rebased_pc) if isinstance(rebased_pc,int) else rebased_pc}")
            return False
        self.decomp_lines = decompilation
        last_line = self.curr_line
        self.curr_line = resp["curr_line"]
        if self.curr_line == -1:
            self.curr_line = last_line if last_line is not None else 0

        self.curr_func = resp["func_name"]

        # update the data known in the function (stack variables)
        self.decompiler.update_function_data(rebased_pc)
        return True

    def display_pane(self):
        """
        Display the current decompilation, with an arrow next to the current line.
        """
        if not self.decompiler.connected:
            return

        if not self.ready_to_display:
            err("Unable to decompile function")
            return

        # configure based on source config
        past_lines_color = "gray"
        nb_lines = 6
        cur_line_color = "green"

        if len(self.decomp_lines) < nb_lines:
            nb_lines = len(self.decomp_lines)

        # use GEF source printing method
        for i in range(self.curr_line - nb_lines + 1, self.curr_line + nb_lines):
            if i < 0:
                continue

            if i < self.curr_line:
                self.print(
                    "{}".format(Color.colorify("  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], ), past_lines_color))
                )

            if i == self.curr_line:
                prefix = "{}{:4d}\t ".format(RIGHT_ARROW[1:], i + 1)
                self.print(Color.colorify("{}{:s}".format(prefix, self.decomp_lines[i]), cur_line_color))

            if i > self.curr_line:
                try:
                    self.print("  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], ))
                except IndexError:
                    break
        return

    def title(self):
        """
        Special note: this function is always called before display_pane
        """
        if not self.decompiler.connected:
            return None

        self.ready_to_display = self.update_event(pc())

        if self.ready_to_display:
            title = "decompiler:{:s}:{:s}:{:d}".format(self.decompiler.name, self.curr_func, self.curr_line+1)
        else:
            title = None

        return title

    def display_pane_and_title(self, *args, **kwargs):

        #
        # title
        #

        title_ = self.title()

        line_color = "gray"
        msg_color = "cyan"
        tty_rows, tty_columns = get_terminal_size()

        if title_ is None:
            self.print(Color.colorify(HORIZONTAL_LINE * tty_columns, line_color))
        else:
            trail_len = len(title_) + 6
            title = ""
            title += Color.colorify("{:{padd}<{width}} ".format("",
                                                                width=max(tty_columns - trail_len, 0),
                                                                padd=HORIZONTAL_LINE),
                                    line_color)
            title += Color.colorify(title_, msg_color)
            title += Color.colorify(" {:{padd}<4}".format("", padd=HORIZONTAL_LINE),
                                    line_color)
            self.print(title)

        #
        # decompilation
        #

        self.display_pane()
        self.print(Color.colorify(HORIZONTAL_LINE * tty_columns, line_color))
