__version__ = "3.8.5"

try:
    from .clients.client import DecompilerClient
    from .clients import GDBClient, GDBDecompilerClient
except ImportError:
    pass
