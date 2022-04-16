from .gdb_client import GDBClient


class GEFClient(GDBClient):
    def __init__(self, ctx_pane_registrar, gef_print, gef_config):
        super(GEFClient, self).__init__()
        self.ctx_pane_registrar = ctx_pane_registrar
        self.dec_pane.print = gef_print
        self.gef_config = gef_config

    def register_decompiler_context_pane(self, decompiler_name):
        self.ctx_pane_registrar("decompilation", self.dec_pane.display_pane, self.dec_pane.title)

    def deregister_decompiler_context_pane(self, decompiler_name):
        print("deregister called!")
        self.gef_config["context.layout"] = self.gef_config["context.layout"].replace(" decompilation", "")
