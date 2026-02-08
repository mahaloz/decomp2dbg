"""
Integration tests for decomp2dbg with GDB and headless decompilers.

This test module contains test suites for each supported decompiler backend:
1. TestGDBIntegrationIDA — uses headless IDA (via idalib)
2. TestGDBIntegrationGhidra — uses headless Ghidra

Each suite starts a headless decompiler server (via libbs), launches GDB
with the fauxware binary, connects decomp2dbg, and verifies decompilation.

NOTE: IDA must run before Ghidra.  Ghidra's JVM shutdown leaves the
process in a state that causes idalib to segfault if initialised afterward.

Requirements:
    - gdb (system)
    - decomp2dbg (pip, editable install from this repo)
    - libbs >= 3.3.0 (pip)
    Ghidra tests:
        - openjdk-21-jdk, pyghidra, libbs[ghidra]
        - GHIDRA_INSTALL_DIR env var
    IDA tests:
        - idapro (pip, from idalib — IDA 9+)
"""

import os
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
import xmlrpc.client
from pathlib import Path

from libbs.api import DecompilerInterface
from libbs.decompilers import GHIDRA_DECOMPILER, IDA_DECOMPILER

from decomp2dbg.server import LibBSDecompilerServer

REPO_ROOT = Path(__file__).resolve().parent
FAUXWARE_PATH = REPO_ROOT / "testing" / "binaries" / "fauxware"
D2D_CLIENT_PATH = REPO_ROOT / "decomp2dbg" / "d2d_client.py"


def _find_free_port():
    """Find a free port to avoid conflicts with other tests."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


class _DecompilerTestBase(unittest.TestCase):
    """
    Base class for decompiler integration tests.

    Subclasses must set:
        DECOMPILER      — libbs decompiler constant (e.g. "ghidra", "ida")
        DECOMPILER_NAME — human-readable name for log messages
        DISCOVER_KWARGS — extra kwargs passed to DecompilerInterface.discover()

    Subclasses may set:
        START_XMLRPC    — if False, skip the XML-RPC listener (useful when the
                          decompiler requires main-thread access, e.g. IDA idalib).
                          Tests should call server methods directly instead.
    """

    DECOMPILER: str = None
    DECOMPILER_NAME: str = None
    DISCOVER_KWARGS: dict = {}
    START_XMLRPC: bool = True

    deci = None
    server = None
    server_thread = None
    port = None

    @classmethod
    def setUpClass(cls):
        if cls is _DecompilerTestBase:
            raise unittest.SkipTest("Base class")

        assert FAUXWARE_PATH.exists(), f"Test binary not found: {FAUXWARE_PATH}"
        assert D2D_CLIENT_PATH.exists(), f"d2d_client.py not found: {D2D_CLIENT_PATH}"

        cls.port = _find_free_port()
        cls._tmpdir = tempfile.TemporaryDirectory()

        print(f"[*] Starting headless {cls.DECOMPILER_NAME} on fauxware (port {cls.port})...")
        discover_kwargs = dict(
            force_decompiler=cls.DECOMPILER,
            headless=True,
            binary_path=str(FAUXWARE_PATH),
        )
        discover_kwargs.update(cls.DISCOVER_KWARGS)
        # Ghidra needs project_location; provide tmpdir for any backend that wants it
        if "project_location" not in discover_kwargs:
            discover_kwargs.setdefault("project_location", cls._tmpdir.name)
            discover_kwargs.setdefault("project_name", f"test_fauxware_{cls.DECOMPILER}")

        cls.deci = DecompilerInterface.discover(**discover_kwargs)

        cls.server = LibBSDecompilerServer(
            deci=cls.deci, host="localhost", port=cls.port
        )

        if cls.START_XMLRPC:
            cls.server_thread = threading.Thread(
                target=cls.server.start_xmlrpc_server, daemon=True
            )
            cls.server_thread.start()

            # Wait for server to be ready
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    proxy = xmlrpc.client.ServerProxy(f"http://localhost:{cls.port}")
                    proxy.ping()
                    break
                except ConnectionRefusedError:
                    time.sleep(0.2)
            else:
                raise RuntimeError(f"{cls.DECOMPILER_NAME} server did not start in time")

        print(f"[+] {cls.DECOMPILER_NAME} server is ready")

    @classmethod
    def tearDownClass(cls):
        if cls.deci is not None:
            cls.deci.shutdown()
        if hasattr(cls, "_tmpdir"):
            cls._tmpdir.cleanup()

    def _run_gdb_script(self, gdb_commands: str, timeout: int = 60) -> str:
        """
        Run a sequence of GDB commands via ``gdb -batch -x <script>``.

        Returns the combined stdout+stderr output.
        """
        # GDB uses the system Python, which may not have decomp2dbg installed.
        # Prepend sys.path with the repo root so GDB can find the package.
        preamble = textwrap.dedent(f"""\
            python
            import sys
            sys.path.insert(0, "{REPO_ROOT}")
            end
        """)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".gdb", delete=False
        ) as f:
            f.write(preamble + gdb_commands)
            script_path = f.name

        try:
            result = subprocess.run(
                ["gdb", "-batch", "-x", script_path, str(FAUXWARE_PATH)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            return output
        finally:
            os.unlink(script_path)


# ======================================================================
# IDA backend  (must run before Ghidra — see module docstring)
# ======================================================================

class TestGDBIntegrationIDA(_DecompilerTestBase):
    """
    End-to-end test: headless IDA server + decomp2dbg.

    NOTE: IDA's idalib requires all API calls on the main thread.  The
    XML-RPC server handles requests on a worker thread, which would
    deadlock.  We therefore skip the XML-RPC listener and call the
    server methods directly (the transport layer is already tested by
    the Ghidra suite).
    """

    DECOMPILER = IDA_DECOMPILER
    DECOMPILER_NAME = "IDA"
    START_XMLRPC = False

    def test_01_decompile_main(self):
        """Verify that decompiling main via IDA returns non-empty lines."""
        # Call server.decompile() directly (not through XML-RPC) because
        # IDA idalib is not thread-safe.
        result = self.server.decompile(0x40071d)

        self.assertIsNotNone(result)
        lines = result.get("decompilation")
        self.assertIsNotNone(lines, "Decompilation returned no lines")
        self.assertGreater(len(lines), 0)

        func_name = result.get("func_name")
        self.assertEqual(func_name, "main", f"Expected main, got {func_name}")

        full_text = "\n".join(lines)
        self.assertTrue(
            "main" in full_text.lower() or "void" in full_text.lower(),
            f"Decompilation text does not look like main:\n{full_text[:300]}",
        )

        print(f"\n[+] IDA decompile_main test passed:")
        print(f"    func_name = {func_name}")
        print(f"    num_lines = {len(lines)}")


# ======================================================================
# Ghidra backend
# ======================================================================

class TestGDBIntegrationGhidra(_DecompilerTestBase):
    """End-to-end test: headless Ghidra server + GDB client with decomp2dbg."""

    DECOMPILER = GHIDRA_DECOMPILER
    DECOMPILER_NAME = "Ghidra"

    # ------------------------------------------------------------------
    # Test 1: XML-RPC server responds correctly
    # ------------------------------------------------------------------
    def test_01_server_ping_and_functions(self):
        """Verify the XML-RPC server is alive and returns function data."""
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        self.assertTrue(proxy.ping())

        headers = proxy.function_headers()
        self.assertGreater(len(headers), 0, "No functions returned")

        # fauxware should have 'main' and 'authenticate'
        func_names = {v["name"] for v in headers.values()}
        self.assertIn("main", func_names)
        self.assertIn("authenticate", func_names)

    # ------------------------------------------------------------------
    # Test 2: Decompile main via XML-RPC
    # ------------------------------------------------------------------
    def test_02_decompile_main(self):
        """Verify that decompiling main returns non-empty lines."""
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        # 0x40071d is the address of main in the fauxware binary
        result = proxy.decompile(0x40071d)

        self.assertIsNotNone(result)
        lines = result.get("decompilation")
        self.assertIsNotNone(lines, "Decompilation returned no lines")
        self.assertGreater(len(lines), 0)

        # The decompilation should mention something recognisable
        full_text = "\n".join(lines)
        self.assertTrue(
            "main" in full_text.lower() or "void" in full_text.lower(),
            f"Decompilation text does not look like main:\n{full_text[:300]}",
        )

    # ------------------------------------------------------------------
    # Test 3: GDB can source d2d_client.py without errors
    # ------------------------------------------------------------------
    def test_03_gdb_source_d2d(self):
        """Verify GDB can source the decomp2dbg client without errors."""
        script = textwrap.dedent(f"""\
            source {D2D_CLIENT_PATH}
            python print("D2D_LOADED_OK")
        """)
        output = self._run_gdb_script(script)
        self.assertIn("D2D_LOADED_OK", output, f"GDB output:\n{output}")

    # ------------------------------------------------------------------
    # Test 4: Full GDB flow – connect, break main, run, get decompilation
    # ------------------------------------------------------------------
    def test_04_gdb_connect_break_main_decompile(self):
        """
        Full integration: source d2d, start fauxware, connect to decompiler
        server, break at main, continue, and verify decompilation output.
        """
        gdb_python = textwrap.dedent(f"""\
            import gdb
            import sys
            import time

            # Source d2d
            gdb.execute("source {D2D_CLIENT_PATH}")

            # Start the inferior (stops at main)
            gdb.execute("start")

            # Connect to the decomp2dbg server
            gdb.execute("decompiler connect ghidra --port {self.port}")

            # Give connection a moment to stabilise
            time.sleep(2)

            # Now manually query decompilation through XML-RPC to verify
            # the server can decompile at the current PC (which is main)
            import xmlrpc.client
            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")
            pc = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)
            print(f"TEST_PC={{pc:#x}}")

            result = proxy.decompile(pc)
            lines = result.get("decompilation") or []
            func_name = result.get("func_name") or "unknown"
            curr_line = result.get("curr_line")

            print(f"TEST_FUNC_NAME={{func_name}}")
            print(f"TEST_NUM_LINES={{len(lines)}}")
            print(f"TEST_CURR_LINE={{curr_line}}")

            if lines:
                # Print a few lines so we can verify
                for i, line in enumerate(lines[:10]):
                    print(f"TEST_DECOMP_{{i}}={{line}}")

            print("TEST_DONE")
        """)

        script = textwrap.dedent(f"""\
            set pagination off
            set confirm off
            python
{textwrap.indent(gdb_python, "            ")}
            end
            quit
        """)

        output = self._run_gdb_script(script, timeout=120)

        # Parse test markers from GDB output
        self.assertIn("TEST_DONE", output, f"GDB script did not complete.\nOutput:\n{output}")

        # Extract values
        def _extract(marker):
            for line in output.splitlines():
                if line.startswith(marker):
                    return line[len(marker):]
            return None

        func_name = _extract("TEST_FUNC_NAME=")
        num_lines = _extract("TEST_NUM_LINES=")
        curr_line = _extract("TEST_CURR_LINE=")

        self.assertIsNotNone(func_name, f"Could not find func_name in output:\n{output}")
        self.assertEqual(func_name, "main", f"Expected main, got {func_name}")

        self.assertIsNotNone(num_lines, f"Could not find num_lines in output:\n{output}")
        self.assertGreater(int(num_lines), 0, "No decompilation lines")

        self.assertIsNotNone(curr_line, f"Could not find curr_line in output:\n{output}")

        # Verify we got decompilation lines that look reasonable
        decomp_line_0 = _extract("TEST_DECOMP_0=")
        self.assertIsNotNone(decomp_line_0, f"No decompilation lines in output:\n{output}")

        print(f"\n[+] GDB integration test passed:")
        print(f"    func_name = {func_name}")
        print(f"    num_lines = {num_lines}")
        print(f"    curr_line = {curr_line}")

    # ------------------------------------------------------------------
    # Test 5: stepi within main – decompile at non-entry addresses
    # ------------------------------------------------------------------
    def test_05_decompile_after_stepi(self):
        """
        Verify decompilation works at addresses *within* main (not just
        the entry point).  This catches Java JInt marshalling errors that
        occur when the line_map cache is hit.
        """
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        # First decompile at main entry to populate the cache
        result = proxy.decompile(0x40071d)
        self.assertIsNotNone(result.get("decompilation"))

        # Now decompile at a few offsets inside main (simulating stepi).
        # These addresses are within main's body in fauxware.
        for offset in [0x400721, 0x400725, 0x400739, 0x400750]:
            result = proxy.decompile(offset)
            self.assertIsNotNone(result, f"decompile({offset:#x}) returned None")

            lines = result.get("decompilation")
            curr_line = result.get("curr_line")
            func_name = result.get("func_name")

            self.assertIsNotNone(lines, f"No lines for {offset:#x}")
            self.assertGreater(len(lines), 0, f"Empty lines for {offset:#x}")

            # curr_line must be a plain int (not a Java JInt)
            if curr_line is not None:
                self.assertIsInstance(curr_line, int,
                                     f"curr_line is {type(curr_line)}, expected int")

            # func_name should still be main
            if func_name is not None:
                self.assertEqual(func_name, "main",
                                 f"Expected main at {offset:#x}, got {func_name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
