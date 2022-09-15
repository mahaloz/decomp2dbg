from .gdb_client import GDBClient
from .utils import is_remote_debug, checksec


class GEFClient(GDBClient):
    def __init__(self, ctx_pane_registrar, gef_print, gef_ref): #gef_config, gef_memory):
        super(GEFClient, self).__init__()
        self.ctx_pane_registrar = ctx_pane_registrar
        self.dec_pane.print = gef_print
        self.gef_config = gef_ref.config
        self.gef_ref = gef_ref

    def register_decompiler_context_pane(self, decompiler_name):
        self.ctx_pane_registrar("decompilation", self.dec_pane.display_pane, self.dec_pane.title)

    def deregister_decompiler_context_pane(self, decompiler_name):
        self.gef_config["context.layout"] = self.gef_config["context.layout"].replace(" decompilation", "")

    def find_text_segment_base_addr(self, is_remote=False):
        if is_remote:
            elf_file = str(self.gef_ref.session.remote.lfile)
            elf_virtual_path = str(self.gef_ref.session.remote.file)
        else:
            elf_file = str(self.gef_ref.session.file)
            elf_virtual_path = str(self.gef_ref.session.file)

        vmmap = self.gef_ref.memory.maps
        base_address = min(x.page_start for x in vmmap if x.path == elf_virtual_path)

        return base_address
    
    @property
    def is_pie(self):
        elf_file = self.gef_ref.session.remote.lfile if is_remote_debug() else self.gef_ref.session.file
        checksec_status = checksec(str(elf_file))
        return checksec_status["PIE"]  # if pie we will have offset instead of abs address.
