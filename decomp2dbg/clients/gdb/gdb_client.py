import textwrap
import argparse
import contextlib
import io

import gdb

from ..client import DecompilerClient
from ...utils import *
from .utils import *
from .symbol_mapper import SymbolMapper
from .decompiler_pane import DecompilerPane

#
# Decompiler Client Interface
#


class GDBDecompilerClient(DecompilerClient):
    def __init__(self, gdb_client, name="decompiler", host="127.0.0.1", port=3662):
        super(GDBDecompilerClient, self).__init__(name=name, host=host, port=port)
        self.gdb_client: "GDBClient" = gdb_client
        self.symbol_mapper = SymbolMapper()
        self._is_pie = None
        self._lvar_bptr = None

    @property
    @lru_cache()
    def text_base_addr(self):
        return self.gdb_client.base_addr_start

    @property
    def is_pie(self):
        if self._is_pie is None:
            self._is_pie = self.gdb_client.is_pie

        return self._is_pie

    def rebase_addr(self, addr, up=False):
        corrected_addr = addr
        if self.is_pie or self.gdb_client.base_manually_set:
            if up:
                corrected_addr += self.text_base_addr
            else:
                corrected_addr -= self.text_base_addr

        return corrected_addr

    def decompiler_connected(self):
        self.gdb_client.on_decompiler_connected(self.name)

    def decompiler_disconnected(self):
        self.gdb_client.on_decompiler_disconnected(self.name)

    def update_symbols(self):
        self.symbol_mapper.text_base_addr = self.text_base_addr

        global_vars, func_headers = self.update_global_vars(), self.update_function_headers()
        syms_to_add = []
        sym_name_set = set()
        global_var_size = 8

        if not self.native_sym_support:
            err("Native symbol support is required to run decomp2dbg, assure you have coreutils installed.")
            return False

        # add symbols with native support if possible
        for addr, func in func_headers.items():
            syms_to_add.append((func["name"], int(addr, 0), "function", func["size"]))
            sym_name_set.add(func["name"])

        for addr, global_var in global_vars.items():
            clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", global_var['name'])
            # never re-add globals with the same name as a func
            if clean_name in sym_name_set:
                continue

            syms_to_add.append((clean_name, int(addr, 0), "object", global_var_size))

        try:
            self.symbol_mapper.add_native_symbols(syms_to_add)
        except Exception as e:
            err(f"Failed to set symbols natively: {e}")
            self.native_sym_support = False
            return False

        return True

    def update_global_vars(self):
        return self.global_vars

    def update_function_headers(self):
        return self.function_headers

    def _clean_type_str(self, type_str):
        if "__" in type_str:
            type_str = type_str.replace("__", "")
            idx = type_str.find("[")
            if idx != -1:
                type_str = type_str[:idx] + "_t" + type_str[idx:]
            else:
                type_str += "_t"
        type_str = type_str.replace("unsigned ", "u")

        return type_str

    def _find_local_var_base_ptr(self):
        if self._lvar_bptr is not None:
            return self._lvar_bptr

        candidates = ["$rbp", "$ebp", "$bp", "$fp"]
        for candidate in candidates:
            # the register must exist
            try:
                val = gdb.parse_and_eval(candidate)
            except Exception:
                continue

            # the register must have a real value
            try:
                int(str(val), 16)
            except Exception:
                continue

            self._lvar_bptr = candidate
            return self._lvar_bptr


    def update_function_data(self, addr):
        func_data = self.function_data(addr)
        reg_vars = func_data.get("reg_vars", {})
        stack_vars = func_data.get("stack_vars", {})

        for name, var in reg_vars.items():
            type_str = self._clean_type_str(var['type'])
            reg_name = var['reg_name']
            expr = f"""(({type_str}) (${reg_name})"""

            try:
                val = gdb.parse_and_eval(expr)
                gdb.execute(f"set ${name} = {val}")
                type_unknown = False
            except Exception:
                type_unknown = True

            if type_unknown:
                try:
                    gdb.execute(f"set ${name} = (${reg_name})")
                except Exception:
                    continue

        for offset, stack_var in stack_vars.items():
            offset = abs(int(offset, 0))
            type_str = self._clean_type_str(stack_var['type'])
            lvar_bptr = self._find_local_var_base_ptr()
            if lvar_bptr == "$rbp":
                offset -= 8
            elif lvar_bptr == "$ebp":
                offset -= 4

            expr = f"""({type_str}*) ({lvar_bptr} - {offset})"""
            var_name = stack_var['name']

            try:
                gdb.execute(f"set ${var_name} = " + expr)
                type_unknown = False
            except Exception:
                type_unknown = True

            if type_unknown:
                try:
                    gdb.execute(f"set ${var_name} = ($fp - {offset})")
                except Exception:
                    continue


#
# Command Interface
#

class DecompilerCommand(gdb.Command):
    def __init__(self, decompiler, gdb_client):
        super(DecompilerCommand, self).__init__("decompiler", gdb.COMMAND_USER)
        self.decompiler = decompiler
        self.gdb_client = gdb_client
        self.arg_parser = self._init_arg_parser()

    @only_if_gdb_running
    def invoke(self, arg, from_tty):
        raw_args = arg.split()
        try:
            f = io.StringIO()
            with contextlib.redirect_stderr(f):
                args = self.arg_parser.parse_args(raw_args)
        except (RuntimeError, RuntimeWarning):
            return
        except Exception as e:
            err(f"Error parsing args: {e}")
            self.arg_parser.print_help()
            return

        self._handle_cmd(args)

    @staticmethod
    def _init_arg_parser():
        parser = argparse.ArgumentParser()
        commands = ["connect", "disconnect", "info"]
        parser.add_argument(
            'command', type=str, choices=commands, help="""
            Commands:
            [connect]: connects a decompiler by name, with optional host, port, and base address.
            [disconnect]: disconnects a decompiler by name, destroyed decompilation panel.
            [info]: lists useful info about connected decompilers
            """
        )
        parser.add_argument(
            'decompiler_name', type=str, nargs="?", help="""
            The name of the decompiler, which can be anything you like. It's suggested
            to use sematic and numeric names like: 'ida2' or 'ghidra1'. Optional when doing 
            the info command.
            """
        )
        parser.add_argument(
            '--host', type=str, default="localhost"
        )
        parser.add_argument(
            '--port', type=int, default=3662
        )
        parser.add_argument(
            '--base-addr-start', type=lambda x: int(x,0)
        )
        parser.add_argument(
            '--base-addr-end', type=lambda x: int(x,0)
        )

        return parser

    def _handle_cmd(self, args):
        cmd = args.command
        handler_str = f"_handle_{cmd}"
        handler = getattr(self, handler_str)
        handler(args)

    def _handle_connect(self, args):
        if not args.decompiler_name:
            err("You must provide a decompiler name when using this command!")
            return

        if (args.base_addr_start and not args.base_addr_end) or (args.base_addr_end and not args.base_addr_start):
            err("You must use --base-addr-start and --base-addr-end together")
            return
        elif args.base_addr_start and args.base_addr_end:
            if args.base_addr_start > args.base_addr_end:
                err("Your provided base-addr-start must be smaller than your base-addr-end")
                return

            self.gdb_client.base_addr_start = args.base_addr_start
            self.gdb_client.base_addr_end = args.base_addr_end
            self.gdb_client.base_manually_set = True

        self.gdb_client.name = args.decompiler_name
        connected = self.decompiler.connect(name=args.decompiler_name, host=args.host, port=args.port)
        if not connected:
            err("Failed to connect to decompiler!")
            return

        info("Connected to decompiler!")

    def _handle_disconnect(self, args):
        if not args.decompiler_name:
            err("You must provide a decompiler name when using this command!")
            return

        self.decompiler.disconnect()
        info("Disconnected decompiler!")

    def _handle_info(self, args):
        info("Decompiler Info:")
        print(textwrap.dedent(
            f"""\
            Name: {self.gdb_client.name}
            Base Addr Start: {hex(self.gdb_client.base_addr_start) 
            if isinstance(self.gdb_client.base_addr_start, int) else self.gdb_client.base_addr_start}
            Base Addr End: {hex(self.gdb_client.base_addr_end)
            if isinstance(self.gdb_client.base_addr_end, int) else self.gdb_client.base_addr_end}
            """
        ))


class GDBClient:
    def __init__(self):
        self.dec_client = GDBDecompilerClient(self)
        self.cmd_interface = DecompilerCommand(self.dec_client, self)
        self.dec_pane = DecompilerPane(self.dec_client)

        self.name = None
        self.base_manually_set = False
        self.base_addr_start = None
        self.base_addr_end = None

    def __del__(self):
        del self.cmd_interface

    def register_decompiler_context_pane(self, decompiler_name):
        gdb.events.stop.connect(self.dec_pane.display_pane_and_title)

    def deregister_decompiler_context_pane(self, decompiler_name):
        gdb.events.stop.disconnect(self.dec_pane.display_pane_and_title)

    def find_text_segment_base_addr(self, is_remote=False):
        return find_text_segment_base_addr(is_remote=is_remote)

    @property
    def is_pie(self):
        checksec_status = checksec(get_filepath())
        return checksec_status["PIE"]  # if pie we will have offset instead of abs address.

    #
    # Event Handlers
    #

    def on_decompiler_connected(self, decompiler_name):
        if self.base_addr_start is None:
            self.base_addr_start = self.find_text_segment_base_addr(is_remote=is_remote_debug())
        self.dec_client.update_symbols()
        self.register_decompiler_context_pane(decompiler_name)

    def on_decompiler_disconnected(self, decompiler_name):
        self.deregister_decompiler_context_pane(decompiler_name)
        self.name = None
        self.base_addr_start = None
        self.base_addr_end = None
