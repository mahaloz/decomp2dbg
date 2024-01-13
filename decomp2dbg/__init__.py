__version__ = "3.8.3"

try:
    from .clients.client import DecompilerClient
    from .clients import GDBClient, GDBDecompilerClient
except ImportError:
    pass
