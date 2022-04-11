from .gdb_client import GDBClient


class GEFClient(GDBClient):
    def __init__(self, ctx_pane_registrar, gef_print):
        super(GEFClient, self).__init__()
        self.ctx_pane_registrar = ctx_pane_registrar
        self.dec_pane.print = gef_print

    def register_decompiler_context_pane(self, decompiler_name):
        self.ctx_pane_registrar("decompilation", self.dec_pane.display_pane, self.dec_pane.title)

    def deregister_decompiler_context_pane(self, decompiler_name):
        pass

