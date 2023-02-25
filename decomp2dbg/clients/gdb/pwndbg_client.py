import sys

import pwndbg

from .gdb_client import GDBClient
from .decompiler_pane import DecompilerPane
from ...utils import *
import xmlrpc.client


class PwndbgDecompilerPane(DecompilerPane):
    def __init__(self, decompiler):
        super(PwndbgDecompilerPane, self).__init__(decompiler)

    def decompilation_text(self):
        """
        Display the current decompilation, with an arrow next to the current line.
        """
        output = []

        if not self.decompiler.connected:
            return output

        if not self.ready_to_display:
            err("Unable to decompile function")
            return output

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
                output += ["{}".format(Color.colorify("  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], ), past_lines_color))]

            if i == self.curr_line:
                prefix = "{}{:4d}\t ".format(RIGHT_ARROW[1:], i + 1)
                output += [Color.colorify("{}{:s}".format(prefix, self.decomp_lines[i]), cur_line_color)]

            if i > self.curr_line:
                try:
                    output += ["  {:4d}\t {:s}".format(i + 1, self.decomp_lines[i], )]
                except IndexError:
                    break
        return output

    def context_gdecompiler(self, target=sys.stdout, with_banner=True, width=None):
        failed = True
        try:
            # triggers an update as well
            pane_title = self.title()
            failed = False
        except Exception as e:
            pane_title = f"decompiler: {e}"

        if pane_title is None:
            return []

        banner = [pwndbg.ui.banner(pane_title, target=target, width=width)] if with_banner else []
        if failed:
            return banner + ["decompilation error"]

        return banner + self.decompilation_text()


class PwndbgClient(GDBClient):
    def __init__(self):
        super(PwndbgClient, self).__init__()
        self.dec_pane = PwndbgDecompilerPane(self.dec_client)

        # if we are connected to ghidra
        if not isinstance(self.dec_client.server, xmlrpc.client.ServerProxy):
            # reset the type handlers pwndbg adds
            xmlrpc.client.Marshaller.dispatch[type(0)] = xmlrpc.client.Marshaller.dump_long

    def register_decompiler_context_pane(self, decompiler_name):
        pwndbg.commands.context.context_sections["g"] = self.dec_pane.context_gdecompiler
        pwndbg.commands.config_context_sections = pwndbg.lib.config.Parameter(
            f'context-sections',
            f'regs disasm code gdecompiler stack backtrace expressions',
            f'which context sections are displayed (controls order)'
        )

    def deregister_decompiler_context_pane(self, decompiler_name):
        del pwndbg.commands.context.context_sections["g"]
        pwndbg.commands.config_context_sections = pwndbg.lib.config.Parameter(
            f'context-sections',
            f'regs disasm code ghidra stack backtrace expressions',
            f'which context sections are displayed (controls order)'
        )
