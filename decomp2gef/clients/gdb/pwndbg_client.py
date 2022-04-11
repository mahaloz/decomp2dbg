from .gdb_client import GDBClient

class PwndbgClient(GDBClient):
    def __init__(self):
        super(PwndbgClient, self).__init__()