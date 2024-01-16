import unittest
import sys
from unittest.mock import Mock

sys.modules["gdb"] = Mock()
from decomp2dbg import GDBDecompilerClient


# run with python -m unittest gdb_client_test.TestGDBDecompilerClient

class TestGDBDecompilerClient(unittest.TestCase):
    def setUp(self) -> None:
        self._symbols = [
            ("f1", 0x100, "function", 0x10),
            ("f2", 0x200, "function", 0x10),
            ("g1", 0x300, "object", 8),
            ("g2", 0x400, "object", 8)
        ]

        self._c = GDBDecompilerClient(None)
        for s in self._symbols:
            self._c._cache(s)

    def test_cache_new_entry(self):
        entry = ("new symbol f3", 0x500, "function", 0x10)
        is_new = self._c._cache(entry)
        self.assertEqual(is_new, True, "entry is not not new")

    def test_cache_old_entry(self):
        existing = self._symbols[0]
        is_new = self._c._cache(existing)
        self.assertEqual(is_new, False, "entry is old, but cache func says it's new")
