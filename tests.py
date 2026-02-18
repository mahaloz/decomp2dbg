"""
Integration tests for decomp2dbg with GDB and headless decompilers.

Test suites:
  - TestGDBIntegrationIDA — headless IDA (via idalib)
  - TestGDBIntegrationGhidra — headless Ghidra

NOTE: IDA must run before Ghidra. Ghidra's JVM shutdown leaves the process
in a state that causes idalib to segfault if initialised afterward.
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
OBJDUMP_PATH = REPO_ROOT / "testing" / "binaries" / "objdump_ubuntu24"
D2D_CLIENT_PATH = REPO_ROOT / "decomp2dbg" / "d2d_client.py"

FAUXWARE_TEXT_BASE = 0x400000
FAUXWARE_MAIN_ADDR = 0x40071d
FAUXWARE_AUTHENTICATE_ADDR = 0x400664
FAUXWARE_ACCEPTED_ADDR = 0x4006ed
FAUXWARE_REJECTED_ADDR = 0x4006fd
FAUXWARE_SNEAKY_ADDR = 0x601048


def _find_free_port():
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
        START_XMLRPC    — if False, skip the XML-RPC listener
    """

    DECOMPILER: str = None
    DECOMPILER_NAME: str = None
    BINARY_PATH: Path = FAUXWARE_PATH
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

        assert cls.BINARY_PATH.exists(), f"Test binary not found: {cls.BINARY_PATH}"
        assert D2D_CLIENT_PATH.exists(), f"d2d_client.py not found: {D2D_CLIENT_PATH}"

        cls.port = _find_free_port()
        cls._tmpdir = tempfile.TemporaryDirectory()

        discover_kwargs = dict(
            force_decompiler=cls.DECOMPILER,
            headless=True,
            binary_path=str(cls.BINARY_PATH),
        )
        discover_kwargs.update(cls.DISCOVER_KWARGS)
        if "project_location" not in discover_kwargs:
            discover_kwargs.setdefault("project_location", cls._tmpdir.name)
            discover_kwargs.setdefault("project_name", f"test_{cls.BINARY_PATH.stem}_{cls.DECOMPILER}")

        cls.deci = DecompilerInterface.discover(**discover_kwargs)

        cls.server = LibBSDecompilerServer(
            deci=cls.deci, host="localhost", port=cls.port
        )

        if cls.START_XMLRPC:
            cls.server_thread = threading.Thread(
                target=cls.server.start_xmlrpc_server, daemon=True
            )
            cls.server_thread.start()

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

    @classmethod
    def tearDownClass(cls):
        if cls.deci is not None:
            try:
                cls.deci.shutdown()
            except Exception:
                pass
        if hasattr(cls, "_tmpdir"):
            cls._tmpdir.cleanup()

    def _run_gdb_script(self, gdb_commands: str, timeout: int = 60) -> str:
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
                ["gdb", "-batch", "-x", script_path, str(self.BINARY_PATH)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr
        finally:
            os.unlink(script_path)

    def _run_gdb_python(self, python_code: str, timeout: int = 120) -> str:
        """
        Wrap Python code in a GDB script that sources d2d, starts the
        inferior, and connects to the test server.
        """
        gdb_python = textwrap.dedent(f"""\
            import gdb
            import sys
            import time

            gdb.execute("source {D2D_CLIENT_PATH}")
            gdb.execute("start")
            gdb.execute("decompiler connect {self.DECOMPILER_NAME.lower()} --port {self.port}")
            time.sleep(2)

        """) + python_code

        script = textwrap.dedent(f"""\
            set pagination off
            set confirm off
            python
{textwrap.indent(gdb_python, "            ")}
            end
            quit
        """)
        return self._run_gdb_script(script, timeout=timeout)

    @staticmethod
    def _extract_marker(output: str, marker: str):
        for line in output.splitlines():
            if line.startswith(marker):
                return line[len(marker):]
        return None


class TestGDBIntegrationIDA(_DecompilerTestBase):
    """
    End-to-end test: headless IDA server + decomp2dbg.

    IDA's idalib requires all API calls on the main thread, so we skip
    the XML-RPC listener and call server methods directly.
    """

    DECOMPILER = IDA_DECOMPILER
    DECOMPILER_NAME = "IDA"
    START_XMLRPC = False

    def test_decompile_main(self):
        result = self.server.decompile(FAUXWARE_MAIN_ADDR)

        self.assertIsNotNone(result)
        lines = result.get("decompilation")
        self.assertIsNotNone(lines, "Decompilation returned no lines")
        self.assertGreater(len(lines), 0)
        self.assertEqual(result.get("func_name"), "main")


class TestGDBIntegrationGhidra(_DecompilerTestBase):
    """End-to-end test: headless Ghidra server + GDB client with decomp2dbg."""

    DECOMPILER = GHIDRA_DECOMPILER
    DECOMPILER_NAME = "Ghidra"

    # -- Server-side API tests --

    def test_function_headers(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        self.assertTrue(proxy.ping())

        headers = proxy.function_headers()
        self.assertGreater(len(headers), 0, "No functions returned")

        func_by_name = {}
        for addr_str, header in headers.items():
            self.assertIn("name", header)
            self.assertIn("size", header)
            self.assertTrue(header["name"], f"Empty function name at {addr_str}")
            self.assertIsInstance(header["size"], int)
            int(addr_str)  # address key must be parseable
            func_by_name[header["name"]] = header

        for name in ["main", "authenticate", "accepted", "rejected"]:
            self.assertIn(name, func_by_name)
            self.assertGreater(func_by_name[name]["size"], 0,
                               f"{name} should have non-zero size")

    def test_decompile_main(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        result = proxy.decompile(FAUXWARE_MAIN_ADDR)

        self.assertIsNotNone(result)
        lines = result.get("decompilation")
        self.assertIsNotNone(lines, "Decompilation returned no lines")
        self.assertGreater(len(lines), 0)

    def test_decompile_mid_function(self):
        """Decompilation works at addresses within main, not just the entry."""
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        for offset in [0x400721, 0x400725, 0x400739, 0x400750]:
            result = proxy.decompile(offset)
            self.assertIsNotNone(result, f"decompile({offset:#x}) returned None")

            lines = result.get("decompilation")
            self.assertIsNotNone(lines, f"No lines for {offset:#x}")
            self.assertGreater(len(lines), 0, f"Empty lines for {offset:#x}")

            curr_line = result.get("curr_line")
            if curr_line is not None:
                self.assertIsInstance(curr_line, int,
                                     f"curr_line is {type(curr_line)}, expected int")

            func_name = result.get("func_name")
            if func_name is not None:
                self.assertEqual(func_name, "main",
                                 f"Expected main at {offset:#x}, got {func_name}")

    def test_decompile_different_functions(self):
        """Each function returns distinct decompilation with the correct name."""
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        main_result = proxy.decompile(FAUXWARE_MAIN_ADDR)
        auth_result = proxy.decompile(FAUXWARE_AUTHENTICATE_ADDR)
        accepted_result = proxy.decompile(FAUXWARE_ACCEPTED_ADDR)
        rejected_result = proxy.decompile(FAUXWARE_REJECTED_ADDR)

        self.assertEqual(main_result["func_name"], "main")
        self.assertEqual(auth_result["func_name"], "authenticate")

        self.assertNotEqual(main_result["decompilation"],
                            auth_result["decompilation"])

        for result in [main_result, auth_result, accepted_result, rejected_result]:
            self.assertIsNotNone(result["decompilation"])
            self.assertGreater(len(result["decompilation"]), 0)
            self.assertIsNotNone(result["curr_line"])

        if accepted_result["func_name"] and rejected_result["func_name"]:
            self.assertNotEqual(accepted_result["func_name"],
                                rejected_result["func_name"])

    def test_global_vars(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        gvars = proxy.global_vars()
        self.assertIsInstance(gvars, dict)

        gvar_names = {v["name"] for v in gvars.values()}
        self.assertIn("sneaky", gvar_names)

        for addr_str, gvar in gvars.items():
            self.assertIn("name", gvar)
            self.assertTrue(gvar["name"], f"Empty name for global at {addr_str}")
            int(addr_str)

    def test_function_data(self):
        """function_data returns stack/register variables for main and authenticate."""
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        for addr, name in [(FAUXWARE_MAIN_ADDR, "main"),
                           (FAUXWARE_AUTHENTICATE_ADDR, "authenticate")]:
            func_data = proxy.function_data(addr)

            self.assertIsInstance(func_data, dict)
            self.assertIn("stack_vars", func_data)
            self.assertIn("reg_vars", func_data)

            stack_vars = func_data["stack_vars"]
            reg_vars = func_data["reg_vars"]

            self.assertIsInstance(stack_vars, list)
            self.assertIsInstance(reg_vars, list)
            self.assertGreater(len(stack_vars) + len(reg_vars), 0,
                               f"{name} should have at least one variable")

            for sv in stack_vars:
                self.assertIn("name", sv)
                self.assertIn("type", sv)
                self.assertTrue(sv["name"], f"Empty stack var name in {name}: {sv}")

            for rv in reg_vars:
                self.assertIn("name", rv)
                self.assertIn("type", rv)
                self.assertIn("reg_name", rv)

    def test_structs(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        structs = proxy.structs()
        self.assertIsInstance(structs, dict)

        for name, struct_info in structs.items():
            self.assertIn("name", struct_info)
            self.assertIn("members", struct_info)
            self.assertEqual(struct_info["name"], name)
            self.assertIsInstance(struct_info["members"], list)

            for member in struct_info["members"]:
                self.assertIn("name", member)
                self.assertIn("type", member)
                self.assertIn("size", member)
                self.assertIn("offset", member)

    def test_versions(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        versions = proxy.versions()
        self.assertIsInstance(versions, dict)
        self.assertIn("name", versions)
        self.assertIn("version", versions)
        self.assertIn("python", versions)
        self.assertEqual(versions["name"], "ghidra")

    def test_binary_path(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")

        bpath = proxy.binary_path()
        self.assertIsInstance(bpath, str)
        self.assertTrue(bpath, "binary_path returned empty string")
        self.assertIn("fauxware", bpath)

    def test_cache_invalidation(self):
        proxy = xmlrpc.client.ServerProxy(f"http://localhost:{self.port}")
        cache = self.server.cache

        proxy.decompile(FAUXWARE_MAIN_ADDR)
        main_internal = self.server.rebase_addr(FAUXWARE_MAIN_ADDR)

        self.assertIsNotNone(cache.get_decompilation(main_internal))

        cache.invalidate_function(main_internal)
        self.assertIsNone(cache.get_decompilation(main_internal))
        self.assertIsNone(cache._function_headers)

        result = proxy.decompile(FAUXWARE_MAIN_ADDR)
        self.assertIsNotNone(result.get("decompilation"))

        cache.invalidate_all()
        self.assertIsNone(cache.get_decompilation(main_internal))
        self.assertIsNone(cache._function_headers)
        self.assertIsNone(cache._global_vars)
        self.assertIsNone(cache._structs)

    def test_rebase_addr_round_trip(self):
        server = self.server

        for addr in [FAUXWARE_MAIN_ADDR, FAUXWARE_AUTHENTICATE_ADDR,
                     FAUXWARE_ACCEPTED_ADDR]:
            internal = server.rebase_addr(addr)
            offset = server.rebase_addr(internal, down=True)
            expected_offset = addr - FAUXWARE_TEXT_BASE
            self.assertEqual(
                offset, expected_offset,
                f"Round-trip failed for {addr:#x}: "
                f"internal={internal:#x}, offset={offset:#x}, "
                f"expected={expected_offset:#x}"
            )

    # -- GDB integration tests --

    def test_gdb_source_d2d(self):
        script = textwrap.dedent(f"""\
            source {D2D_CLIENT_PATH}
            python print("D2D_LOADED_OK")
        """)
        output = self._run_gdb_script(script)
        self.assertIn("D2D_LOADED_OK", output, f"GDB output:\n{output}")

    def test_gdb_connect_and_decompile_at_main(self):
        python_code = textwrap.dedent(f"""\
            import xmlrpc.client

            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")
            pc = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)

            result = proxy.decompile(pc)
            func_name = result.get("func_name") or "unknown"
            lines = result.get("decompilation") or []
            curr_line = result.get("curr_line")

            print(f"TEST_FUNC_NAME={{func_name}}")
            print(f"TEST_NUM_LINES={{len(lines)}}")
            print(f"TEST_CURR_LINE={{curr_line}}")
            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"GDB script did not complete.\nOutput:\n{output}")

        func_name = self._extract_marker(output, "TEST_FUNC_NAME=")
        num_lines = self._extract_marker(output, "TEST_NUM_LINES=")
        curr_line = self._extract_marker(output, "TEST_CURR_LINE=")

        self.assertEqual(func_name, "main")
        self.assertIsNotNone(num_lines)
        self.assertGreater(int(num_lines), 0)
        self.assertIsNotNone(curr_line)

    def test_gdb_breakable_and_inspectable_symbols(self):
        """Function names from the decompiler work as GDB breakpoints and with x/i."""
        python_code = textwrap.dedent(f"""\
            for func in ["authenticate", "accepted", "rejected"]:
                try:
                    gdb.execute(f"b {{func}}")
                    print(f"TEST_BP_{{func}}=OK")
                except Exception as e:
                    print(f"TEST_BP_{{func}}=FAIL:{{e}}")

                try:
                    output = gdb.execute(f"x/10i {{func}}", to_string=True)
                    lines = [l for l in output.strip().splitlines() if l.strip()]
                    if len(lines) >= 5:
                        print(f"TEST_EXAMINE_{{func}}=OK")
                    else:
                        print(f"TEST_EXAMINE_{{func}}=FAIL:only {{len(lines)}} lines")
                except Exception as e:
                    print(f"TEST_EXAMINE_{{func}}=FAIL:{{e}}")

            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        for func in ["authenticate", "accepted", "rejected"]:
            self.assertEqual(self._extract_marker(output, f"TEST_BP_{func}="), "OK",
                             f"Could not break on {func}:\n{output}")
            self.assertEqual(self._extract_marker(output, f"TEST_EXAMINE_{func}="), "OK",
                             f"Could not examine {func}:\n{output}")

    def test_gdb_global_vars(self):
        """Global variable names from the decompiler are accessible in GDB."""
        python_code = textwrap.dedent(f"""\
            try:
                output = gdb.execute("x/gx &sneaky", to_string=True)
                if "0x" in output:
                    print("TEST_SNEAKY_EXAMINE=OK")
                else:
                    print(f"TEST_SNEAKY_EXAMINE=FAIL:{{output}}")
            except Exception as e:
                print(f"TEST_SNEAKY_EXAMINE=FAIL:{{e}}")

            try:
                output = gdb.execute("info address sneaky", to_string=True)
                if "0x" in output.lower() or "symbol" in output.lower():
                    print("TEST_SNEAKY_INFO=OK")
                else:
                    print(f"TEST_SNEAKY_INFO=FAIL:{{output}}")
            except Exception as e:
                print(f"TEST_SNEAKY_INFO=FAIL:{{e}}")

            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_SNEAKY_EXAMINE="), "OK",
                         f"Could not examine sneaky:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_SNEAKY_INFO="), "OK",
                         f"Could not get info for sneaky:\n{output}")

    def test_gdb_convenience_variables(self):
        """Stack/register variables available as GDB convenience variables after stop."""
        python_code = textwrap.dedent(f"""\
            import xmlrpc.client

            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")
            pc = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)

            func_data = proxy.function_data(pc)
            stack_vars = func_data.get("stack_vars", [])
            reg_vars = func_data.get("reg_vars", [])

            all_var_names = [sv["name"] for sv in stack_vars] + [rv["name"] for rv in reg_vars]
            print(f"TEST_TOTAL_VARS={{len(all_var_names)}}")

            gdb.execute("stepi")
            import time
            time.sleep(1)

            found_vars = []
            for name in all_var_names:
                try:
                    val = gdb.execute(f"print ${{name}}", to_string=True)
                    if "void" not in val.lower() and "error" not in val.lower():
                        found_vars.append(name)
                except Exception:
                    pass

            print(f"TEST_NUM_FOUND={{len(found_vars)}}")
            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")

        total_vars = self._extract_marker(output, "TEST_TOTAL_VARS=")
        num_found = self._extract_marker(output, "TEST_NUM_FOUND=")

        self.assertIsNotNone(total_vars)
        self.assertGreater(int(total_vars), 0, "Server returned no variables for main")
        self.assertIsNotNone(num_found)
        self.assertGreater(int(num_found), 0,
                           f"No convenience variables set in GDB.\n"
                           f"Output:\n{output}")

    def test_gdb_step_into_function(self):
        """Stepping from main into authenticate updates the decompilation context."""
        python_code = textwrap.dedent(f"""\
            import xmlrpc.client

            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")

            gdb.execute("b authenticate")
            gdb.execute("continue")

            import time
            time.sleep(1)

            pc = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)
            result = proxy.decompile(pc)
            func_name = result.get("func_name")
            lines = result.get("decompilation") or []

            if func_name == "authenticate" and len(lines) > 0:
                print("TEST_STEP_INTO=OK")
            else:
                print(f"TEST_STEP_INTO=FAIL:func={{func_name}},lines={{len(lines)}}")

            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_STEP_INTO="), "OK",
                         f"Step into authenticate failed:\n{output}")

    def test_gdb_info(self):
        """'decompiler info' shows the decompiler name and base address."""
        python_code = textwrap.dedent(f"""\
            try:
                info_output = gdb.execute("decompiler info", to_string=True)

                has_name = "ghidra" in info_output.lower() or "Name" in info_output
                has_base = "Base" in info_output or "0x" in info_output

                print(f"TEST_INFO_NAME={{'OK' if has_name else 'FAIL'}}")
                print(f"TEST_INFO_BASE={{'OK' if has_base else 'FAIL'}}")
            except Exception as e:
                print(f"TEST_INFO_NAME=FAIL:{{e}}")
                print(f"TEST_INFO_BASE=FAIL:{{e}}")

            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_INFO_NAME="), "OK",
                         f"Info missing decompiler name:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_INFO_BASE="), "OK",
                         f"Info missing base address:\n{output}")

    def test_gdb_disconnect(self):
        python_code = textwrap.dedent(f"""\
            try:
                gdb.execute("decompiler info", to_string=True)
                print("TEST_CONNECTED=OK")
            except Exception as e:
                print(f"TEST_CONNECTED=FAIL:{{e}}")

            try:
                gdb.execute("decompiler disconnect ghidra")
                print("TEST_DISCONNECT=OK")
            except Exception as e:
                print(f"TEST_DISCONNECT=FAIL:{{e}}")

            print("TEST_DONE")
        """)

        output = self._run_gdb_python(python_code)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_CONNECTED="), "OK",
                         f"Was not connected:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_DISCONNECT="), "OK",
                         f"Disconnect failed:\n{output}")

    def test_gdb_connect_with_base_addr(self):
        """Connecting with --base-addr-start/--base-addr-end sets the range correctly."""
        base_start = 0x400000
        base_end = 0x401000

        python_code = textwrap.dedent(f"""\
            import gdb
            import time

            gdb.execute("source {D2D_CLIENT_PATH}")
            gdb.execute("start")

            gdb.execute("decompiler connect ghidra --port {self.port} "
                        "--base-addr-start {base_start:#x} --base-addr-end {base_end:#x}")
            time.sleep(2)

            try:
                info_output = gdb.execute("decompiler info", to_string=True)

                if "{base_start:#x}" in info_output.lower() or "0x400000" in info_output.lower():
                    print("TEST_BASE_START=OK")
                else:
                    print(f"TEST_BASE_START=FAIL:not in info")

                if "{base_end:#x}" in info_output.lower() or "0x401000" in info_output.lower():
                    print("TEST_BASE_END=OK")
                else:
                    print(f"TEST_BASE_END=FAIL:not in info")

            except Exception as e:
                print(f"TEST_BASE_START=FAIL:{{e}}")
                print(f"TEST_BASE_END=FAIL:{{e}}")

            import xmlrpc.client
            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")
            result = proxy.decompile({FAUXWARE_MAIN_ADDR})
            if result.get("decompilation"):
                print("TEST_DECOMP_WITH_BASE=OK")
            else:
                print("TEST_DECOMP_WITH_BASE=FAIL")

            print("TEST_DONE")
        """)

        script = textwrap.dedent(f"""\
            set pagination off
            set confirm off
            python
{textwrap.indent(python_code, "            ")}
            end
            quit
        """)
        output = self._run_gdb_script(script, timeout=120)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_BASE_START="), "OK",
                         f"Base addr start not set:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_BASE_END="), "OK",
                         f"Base addr end not set:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_DECOMP_WITH_BASE="), "OK",
                         f"Decompilation failed with manual base:\n{output}")


class TestGDBIntegrationGhidraPIE(_DecompilerTestBase):
    """End-to-end test: headless Ghidra + GDB with a stripped PIE binary (objdump_ubuntu24)."""

    DECOMPILER = GHIDRA_DECOMPILER
    DECOMPILER_NAME = "Ghidra"
    BINARY_PATH = OBJDUMP_PATH

    def test_server_has_functions(self):
        """Server should discover functions in the PIE binary."""
        headers = self.server.function_headers()
        self.assertGreater(len(headers), 0, "No function headers for PIE binary")

        # Ghidra should find the ELF entry point
        entry_funcs = [v for v in headers.values() if v["name"] == "entry"]
        self.assertTrue(len(entry_funcs) > 0, "Ghidra did not identify 'entry' function")

    def test_gdb_pie_break_step_and_symbol(self):
        """PIE binary: break at entry, step with decompilation, use a synced symbol."""
        python_code = textwrap.dedent(f"""\
            import gdb
            import time
            import xmlrpc.client

            gdb.execute("source {D2D_CLIENT_PATH}")

            # PIE stripped binary has no 'main' symbol in ELF; use starti to
            # stop at the dynamic linker entry, then let d2d sync symbols.
            gdb.execute("starti")

            gdb.execute("decompiler connect {self.DECOMPILER_NAME.lower()} --port {self.port}")
            time.sleep(3)

            # 1. Break at 'entry' — synced from Ghidra, not present in ELF
            try:
                gdb.execute("break entry")
                print("TEST_BREAK=OK")
            except Exception as e:
                print(f"TEST_BREAK=FAIL:{{e}}")
                print("TEST_DONE")
                import sys; sys.exit(0)

            gdb.execute("continue")
            time.sleep(1)

            # Find the text base for rebasing addresses sent over XML-RPC
            # (XML-RPC only supports 32-bit ints; d2d sends offsets, not absolute addrs)
            maps = gdb.execute("info proc mappings", to_string=True)
            text_base = None
            for line in maps.splitlines():
                if "objdump" in line:
                    text_base = int(line.strip().split()[0], 16)
                    break

            proxy = xmlrpc.client.ServerProxy("http://localhost:{self.port}")
            pc = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)
            rebased_pc = pc - text_base if text_base else pc
            result = proxy.decompile(rebased_pc)
            lines = result.get("decompilation") or []

            if len(lines) > 0:
                print("TEST_DECOMP=OK")
            else:
                func_name = result.get("func_name") or "unknown"
                print(f"TEST_DECOMP=FAIL:func={{func_name}},lines={{len(lines)}}")

            # 2. Step and verify decompilation still works
            gdb.execute("stepi")
            time.sleep(1)

            pc2 = int(gdb.execute("print/x $pc", to_string=True).split()[-1], 16)
            rebased_pc2 = pc2 - text_base if text_base else pc2
            result2 = proxy.decompile(rebased_pc2)
            lines2 = result2.get("decompilation") or []

            if len(lines2) > 0:
                print("TEST_STEP_DECOMP=OK")
            else:
                print("TEST_STEP_DECOMP=FAIL")

            # 3. Use a synced symbol — examine instructions at 'entry'
            try:
                output = gdb.execute("x/5i entry", to_string=True)
                insn_lines = [l for l in output.strip().splitlines() if l.strip()]
                if len(insn_lines) >= 3:
                    print("TEST_SYMBOL_USE=OK")
                else:
                    print(f"TEST_SYMBOL_USE=FAIL:only_{{len(insn_lines)}}_lines")
            except Exception as e:
                print(f"TEST_SYMBOL_USE=FAIL:{{e}}")

            print("TEST_DONE")
        """)

        script = textwrap.dedent(f"""\
            set pagination off
            set confirm off
            python
{textwrap.indent(python_code, "            ")}
            end
            quit
        """)
        output = self._run_gdb_script(script, timeout=180)

        self.assertIn("TEST_DONE", output, f"Script did not complete:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_BREAK="), "OK",
                         f"Could not break at synced symbol in PIE binary:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_DECOMP="), "OK",
                         f"Decompilation failed at entry:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_STEP_DECOMP="), "OK",
                         f"No decompilation after stepping:\n{output}")
        self.assertEqual(self._extract_marker(output, "TEST_SYMBOL_USE="), "OK",
                         f"Could not use synced symbol:\n{output}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
