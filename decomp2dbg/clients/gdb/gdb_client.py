import textwrap

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

    @property
    @lru_cache
    def text_base_addr(self):
        return self.gdb_client.text_segment_base_addr

    def rebase_addr(self, addr, up=False):
        checksec_status = checksec(get_filepath())
        pie = checksec_status["PIE"]  # if pie we will have offset instead of abs address.
        corrected_addr = addr
        if pie:
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
            # never re-add globals with the same name as a func
            if global_var["name"] in sym_name_set:
                continue

            syms_to_add.append((global_var["name"], int(addr, 0), "object", global_var_size))

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

    def update_function_data(self, addr):
        func_data = self.function_data(addr)
        args = func_data["args"]
        stack_vars = func_data["stack_vars"]
        arch_args = get_arch_func_args()

        for idx, arg in list(args.items())[:len(arch_args)]:
            idx = int(idx, 0)
            expr = f"""(({arg['type']}) {arch_args[idx]}"""

            try:
                val = gdb.parse_and_eval(expr)
                gdb.execute(f"set ${arg['name']} {val}")
                continue
            except Exception:
                pass

            try:
                gdb.execute(f'set ${arg["name"]} NA')
            except Exception:
                pass

        for offset, stack_var in stack_vars.items():
            offset = int(offset, 0)
            if "__" in  stack_var["type"]:
                stack_var["type"] = stack_var["type"].replace("__", "")
                idx = stack_var["type"].find("[")
                if idx != -1:
                    stack_var["type"] = stack_var["type"][:idx] + "_t" + stack_var["type"][idx:]
                else:
                    stack_var["type"] += "_t"
            stack_var["type"] = stack_var["type"].replace("unsigned ", "u")

            expr = f"""({stack_var['type']}*) ($fp -  {offset})"""

            try:
                gdb.execute(f"set ${stack_var['name']} = " + expr)
                type_unknown = False
            except Exception:
                type_unknown = True

            if type_unknown:
                try:
                    gdb.execute(f"set ${stack_var['name']} = ($fp - {offset})")
                except Exception:
                    continue


#
# Command Interface
#

class DecompilerCommand(gdb.Command):
    def __init__(self, decompiler):
        super(DecompilerCommand, self).__init__("decompiler", gdb.COMMAND_USER)
        self.decompiler = decompiler

    @only_if_gdb_running
    def invoke(self, arg, from_tty):
        args = arg.split(" ")
        if len(args) < 2:
            self._handle_help(None)
            return

        cmd = args[0]
        args = args[1:]
        self._handle_cmd(cmd, args)

    def _handle_cmd(self, cmd, args):
        handler_str = f"_handle_{cmd}"
        if hasattr(self, handler_str):
            handler = getattr(self, handler_str)
            handler(args)
        else:
            self._handler_failed("command does not exist")

    def _handle_connect(self, args):
        if len(args) < 1:
            self._handler_failed("not enough args")
            return

        name = args[0]
        host = "localhost"
        port = 3662

        if len(args) > 1:
            try:
                port_ = int(args[1])
                port = port_
            except ValueError:
                host = args[1]

        if len(args) > 2:
            try:
                port_ = int(args[2])
                port = port_
            except ValueError:
                host = args[2]

        connected = self.decompiler.connect(name=name, host=host, port=port)
        if not connected:
            err("Failed to connect to decompiler!")
            return

        info("Connected to decompiler!")

    def _handle_disconnect(self, args):
        self.decompiler.disconnect()
        info("Disconnected decompiler!")

    def _handle_help(self, args):
        usage_str = """\
        Usage: decompiler <command>

        Commands:
            [] connect <name> (host) (port)
                Connects the decomp2dbg plugin to the decompiler. After a successful connect, a decompilation pane
                will be visible that will get updated with global decompiler info on each break-like event.

                * name = name of the decompiler, can be anything
                * host = host of the decompiler; will be 'localhost' if not defined
                * port = port of the decompiler; will be 3662 if not defined

            [] disconnect
                Disconnects the decomp2dbg plugin. Not needed to stop decompiler, but useful.

        Examples:
            decompiler connect ida
            decompiler connect binja 192.168.15 3662
            decompiler disconnect

        """
        pprint(textwrap.dedent(usage_str))

    def _handler_failed(self, error):
        pprint(f"[!] Failed to handle decompiler command: {error}.")
        self._handle_help(None)


class GDBClient:
    def __init__(self):
        self.dec_client = GDBDecompilerClient(self)
        self.cmd_interface = DecompilerCommand(self.dec_client)
        self.dec_pane = DecompilerPane(self.dec_client)

        self.text_segment_base_addr = None

    def __del__(self):
        del self.cmd_interface

    def register_decompiler_context_pane(self, decompiler_name):
        gdb.events.stop.connect(self.dec_pane.display_pane_and_title)

    def deregister_decompiler_context_pane(self, decompiler_name):
        gdb.events.stop.disconnect(self.dec_pane.display_pane_and_title)

    #
    # Event Handlers
    #

    def on_decompiler_connected(self, decompiler_name):
        if not self.text_segment_base_addr:
            self.text_segment_base_addr = find_text_segment_base_addr(is_remote=is_remote_debug())

        self.dec_client.update_symbols()
        self.register_decompiler_context_pane(decompiler_name)

    def on_decompiler_disconnected(self, decompiler_name):
        self.deregister_decompiler_context_pane(decompiler_name)
