#
# ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ███╗██████╗ ██████╗ ██████╗ ██████╗  ██████╗
# ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔══██╗╚════██╗██╔══██╗██╔══██╗██╔════╝
# ██║  ██║█████╗  ██║     ██║   ██║██╔████╔██║██████╔╝ █████╔╝██║  ██║██████╔╝██║  ███╗
# ██║  ██║██╔══╝  ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔═══╝ ██║  ██║██╔══██╗██║   ██║
# ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██████╔╝██████╔╝╚██████╔╝
# ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═════╝ ╚═════╝  ╚═════╝
#                         Unified DecLib Server
#
# A unified decompiler server using declib DecompilerInterface.
# Works across IDA, Binary Ninja, Ghidra (via pyhidra), and angr.
#

from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from typing import Dict, List, Optional, Tuple, Set
import bisect
import sys

from declib.api import DecompilerInterface
from declib.artifacts import (
    FunctionHeader, StackVariable, Comment, GlobalVariable, Struct, Decompilation
)


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class DecompilationCache:
    """
    Cache decompilations with inverted line maps for O(1) address lookup.

    The declib line_map provides: line_num -> Set[addresses_on_that_line]
    We invert this to: address -> (func_addr, line_num) for fast curr_line lookup.
    """

    def __init__(self):
        # func_addr -> Decompilation artifact
        self._decompilations: Dict[int, Decompilation] = {}
        # any_addr -> (func_addr, line_num) for O(1) line lookup
        self._addr_to_line: Dict[int, Tuple[int, int]] = {}
        # Cached API responses
        self._function_headers: Optional[Dict] = None
        self._global_vars: Optional[Dict] = None
        self._structs: Optional[Dict] = None
        # func_addr -> function_data API response
        self._function_data: Dict[int, dict] = {}
        # sorted (start, end, name) of every function, for containing-function lookup
        self._function_ranges: Optional[List[Tuple[int, int, str]]] = None
        self._function_starts: List[int] = []

    def _build_addr_to_line_index(self, func_addr: int, line_map: Dict[int, Set[int]]):
        """Build the inverted index from addresses to line numbers."""
        if not line_map:
            return
        for line_num, addrs in line_map.items():
            if addrs is None:
                continue
            for addr in addrs:
                # Coerce to native Python int to avoid Java JInt from Ghidra/pyghidra
                self._addr_to_line[int(addr)] = (int(func_addr), int(line_num))

    def get_line_for_addr(self, addr: int) -> Optional[Tuple[int, int]]:
        """Get (func_addr, line_num) for a given address, or None if not cached."""
        return self._addr_to_line.get(addr)

    def set_line_for_addr(self, addr: int, func_addr: int, line_num: int):
        """Remember the line resolved for an address not directly in the line map."""
        self._addr_to_line[int(addr)] = (int(func_addr), int(line_num))

    def get_function_data(self, func_addr: int) -> Optional[dict]:
        return self._function_data.get(func_addr)

    def store_function_data(self, func_addr: int, data: dict):
        self._function_data[func_addr] = data

    def store_function_ranges(self, ranges: List[Tuple[int, int, str]]):
        self._function_ranges = sorted(ranges)
        self._function_starts = [start for start, _, _ in self._function_ranges]

    def get_containing_function(self, addr: int) -> Optional[Tuple[int, str]]:
        """Get (func_addr, func_name) of the function containing addr, or None."""
        if not self._function_ranges:
            return None
        idx = bisect.bisect_right(self._function_starts, addr) - 1
        if idx < 0:
            return None
        start, end, name = self._function_ranges[idx]
        if start <= addr < end:
            return start, name
        return None

    def get_decompilation(self, func_addr: int) -> Optional[Decompilation]:
        """Get cached decompilation for a function address."""
        return self._decompilations.get(func_addr)

    def store_decompilation(self, func_addr: int, decomp: Decompilation):
        """Store a decompilation and build its address-to-line index."""
        self._decompilations[func_addr] = decomp
        if decomp.line_map:
            self._build_addr_to_line_index(func_addr, decomp.line_map)

    def invalidate_function(self, func_addr: int):
        """Invalidate cache for a specific function."""
        if func_addr in self._decompilations:
            # Remove address-to-line mappings for this function
            addrs_to_remove = [
                addr for addr, (faddr, _) in self._addr_to_line.items()
                if faddr == func_addr
            ]
            for addr in addrs_to_remove:
                del self._addr_to_line[addr]
            del self._decompilations[func_addr]
        self._function_data.pop(func_addr, None)
        # Also invalidate function headers since function may have changed
        self.invalidate_function_headers()

    def invalidate_function_headers(self):
        """Invalidate the function headers cache."""
        self._function_headers = None
        self._function_ranges = None
        self._function_starts = []

    def invalidate_global_vars(self):
        """Invalidate the global vars cache."""
        self._global_vars = None

    def invalidate_structs(self):
        """Invalidate the structs cache."""
        self._structs = None

    def invalidate_all(self):
        """Invalidate all caches."""
        self._decompilations.clear()
        self._addr_to_line.clear()
        self._function_data.clear()
        self.invalidate_function_headers()
        self._global_vars = None
        self._structs = None


class DecLibDecompilerServer:
    """
    XML-RPC server using declib DecompilerInterface internally.

    Provides the same API as the original d2d servers but uses declib
    for unified decompiler access across IDA, Binary Ninja, Ghidra, and angr.
    """

    def __init__(self, deci: Optional[DecompilerInterface] = None, host: str = "localhost", port: int = 3662):
        """
        Initialize the server.

        Args:
            deci: Optional DecompilerInterface instance. If None, will auto-discover.
            host: Host address for XML-RPC server.
            port: Port for XML-RPC server.
        """
        self.host = host
        self.port = port
        self.deci = deci if deci is not None else DecompilerInterface.discover()
        self.cache = DecompilationCache()
        self._base_addr: Optional[int] = None

        # Register artifact change callbacks for cache invalidation
        self._register_artifact_callbacks()

        # Pre-populate caches
        self.function_headers()
        self.global_vars()

    def _register_artifact_callbacks(self):
        """Register declib artifact change callbacks for cache invalidation."""
        # Function header changes -> invalidate that function's cache
        self.deci.artifact_change_callbacks[FunctionHeader].append(
            lambda fh, **kw: self.cache.invalidate_function(fh.addr)
        )

        # Stack variable changes -> invalidate containing function
        self.deci.artifact_change_callbacks[StackVariable].append(
            lambda sv, **kw: self.cache.invalidate_function(sv.addr)
        )

        # Comment changes -> invalidate containing function
        self.deci.artifact_change_callbacks[Comment].append(
            lambda cmt, **kw: self._invalidate_containing_function(cmt.addr)
        )

        # Global var changes -> invalidate global_vars cache
        self.deci.artifact_change_callbacks[GlobalVariable].append(
            lambda gv, **kw: self.cache.invalidate_global_vars()
        )

        # Struct changes -> invalidate structs cache
        self.deci.artifact_change_callbacks[Struct].append(
            lambda s, **kw: self.cache.invalidate_structs()
        )

    def _invalidate_containing_function(self, addr: int):
        """Invalidate the function containing the given address."""
        # Check if we have a cached line mapping for this address
        cached = self.cache.get_line_for_addr(addr)
        if cached:
            func_addr, _ = cached
            self.cache.invalidate_function(func_addr)
            return

        # Otherwise, find the function containing this address
        try:
            func = self.deci.get_func_containing(addr)
            if func:
                self.cache.invalidate_function(func.addr)
        except (NotImplementedError, Exception):
            # If we can't find the function, invalidate all decompilations
            self.cache.invalidate_all()

    def _containing_function(self, addr: int) -> Optional[Tuple[int, str]]:
        """
        Get (func_addr, func_name) of the function containing addr, using a cached
        range index so that no decompilation is needed to resolve it.
        """
        if self.cache._function_ranges is None:
            ranges = []
            try:
                for func_addr, func in self.deci.functions.items():
                    func_addr = int(func_addr)
                    size = int(func.size) if func.size else 1
                    ranges.append((func_addr, func_addr + size, str(func.name) if func.name else ""))
            except Exception as e:
                print(f"[decomp2dbg] Failed to build function ranges: {e}")
            self.cache.store_function_ranges(ranges)

        return self.cache.get_containing_function(addr)

    @property
    def base_addr(self) -> int:
        """Get the binary base address."""
        if self._base_addr is None:
            self._base_addr = self.deci.binary_base_addr
        return self._base_addr

    def rebase_addr(self, addr: int, down: bool = False) -> int:
        """
        Convert between GDB client addresses and decompiler-internal addresses
        using the declib art_lifter for correct cross-decompiler support.

        Args:
            addr: The address to convert.
            down: If True, convert decompiler-internal -> GDB offset (for sending to client).
                  If False, convert GDB address -> decompiler-internal (for receiving from client).
        """
        if down:
            # decompiler-internal -> absolute -> offset from binary base
            abs_addr = self.deci.art_lifter.lower_addr(addr)
            return abs_addr - self.base_addr
        else:
            # GDB address -> decompiler-internal
            # If addr < base_addr, treat as PIE offset and add base to get absolute
            if addr < self.base_addr:
                abs_addr = addr + self.base_addr
            else:
                abs_addr = addr
            return self.deci.art_lifter.lift_addr(abs_addr)

    #
    # Public XML-RPC API
    #

    def decompile(self, addr: int) -> dict:
        """
        Decompile the function containing the given address.

        Returns a dict with:
            - decompilation: List of decompiled lines (or None)
            - curr_line: Current line number (0-indexed, or None)
            - func_name: Function name (or None)
        """
        resp = {
            "decompilation": None,
            "curr_line": None,
            "func_name": None,
        }

        addr = self.rebase_addr(addr)

        # Resolve the containing function without decompiling, so that every address
        # in an already decompiled function is served from the cache
        containing = self._containing_function(addr)
        cached_line = self.cache.get_line_for_addr(addr)
        if containing is not None:
            func_addr, func_name = containing
        elif cached_line is not None:
            func_addr, func_name = cached_line[0], None
        else:
            func_addr, func_name = None, None

        decomp = self.cache.get_decompilation(func_addr) if func_addr is not None else None
        if decomp is None:
            # Decompile with line mapping enabled
            try:
                decomp = self.deci.decompile(addr, map_lines=True)
            except Exception as e:
                print(f"[decomp2dbg] Decompilation failed: {e}")
                return resp

            if decomp is None or decomp.text is None:
                return resp

            # Store in cache
            self.cache.store_decompilation(decomp.addr, decomp)
            cached_line = self.cache.get_line_for_addr(addr)

        func_addr = int(decomp.addr)
        if containing is None or containing[0] != func_addr:
            # the range index disagrees with the decompiler, trust the decompiler
            func_name = None

        # Get decompilation lines
        resp["decompilation"] = decomp.text.split('\n')

        # Find current line from line_map
        # Note: coerce to int() to avoid Java JInt objects from Ghidra/pyghidra
        # leaking into the XML-RPC response (which cannot marshal them).
        if cached_line is not None and cached_line[0] == func_addr:
            resp["curr_line"] = int(cached_line[1])
        elif decomp.line_map:
            # Address not found directly, find closest and remember it
            closest = self._find_closest_line(addr, decomp.line_map)
            if closest is not None:
                resp["curr_line"] = int(closest)
                self.cache.set_line_for_addr(addr, func_addr, closest)

        # Get function name
        if func_name:
            resp["func_name"] = func_name
        else:
            try:
                func = self.deci.fast_get_function(func_addr)
                resp["func_name"] = str(func.name) if func else None
            except (NotImplementedError, Exception):
                # Fallback: try to get from functions dict
                try:
                    func = self.deci.functions.get(func_addr)
                    resp["func_name"] = str(func.name) if func else None
                except Exception:
                    pass

        return resp

    def _find_closest_line(self, target_addr: int, line_map: Dict[int, Set[int]]) -> Optional[int]:
        """Find the line number with an address closest to target_addr."""
        best_line = None
        best_distance = float('inf')

        for line_num, addrs in line_map.items():
            if not addrs:
                continue
            for addr in addrs:
                distance = abs(int(addr) - int(target_addr))
                if distance < best_distance:
                    best_distance = distance
                    best_line = int(line_num)

        return best_line

    def function_data(self, addr: int) -> dict:
        """
        Get stack variables and register variables for the function at addr.

        Returns a dict with:
            - stack_vars: List of stack variable dicts
            - reg_vars: List of register variable dicts
        """
        resp = {
            "stack_vars": [],
            "reg_vars": []
        }

        addr = self.rebase_addr(addr)
        containing = self._containing_function(addr)
        func_addr = containing[0] if containing is not None else addr

        cached = self.cache.get_function_data(func_addr)
        if cached is not None:
            return cached

        try:
            # Get the function at this address. Avoid functions.get(), which looks the
            # function up twice (and decompiles twice on Ghidra).
            try:
                func = self.deci.functions[func_addr]
            except KeyError:
                func = None
            if func is None:
                # Try to find function containing this address
                func = self.deci.get_func_containing(addr)

            if func is None:
                return resp

            # Get stack variables
            # Note: coerce all values to native Python types to avoid Java objects
            # from Ghidra/pyghidra leaking into the XML-RPC response.
            for offset, svar in func.stack_vars.items():
                stack_var_info = {
                    "name": str(svar.name) if svar.name else "",
                    "type": str(svar.type) if svar.type else "",
                    "from_sp": None,
                    "from_frame": str(abs(int(offset))) if offset is not None else None,
                }
                resp["stack_vars"].append(stack_var_info)

            # Get function arguments as register variables
            if func.header and func.header.args:
                for arg_offset, arg in func.header.args.items():
                    reg_var_info = {
                        "name": str(arg.name) if arg.name else "",
                        "type": str(arg.type) if arg.type else "",
                        "reg_name": f"arg{int(arg_offset)}",
                    }
                    resp["reg_vars"].append(reg_var_info)

        except Exception as e:
            print(f"[decomp2dbg] function_data failed: {e}")
            return resp

        self.cache.store_function_data(func_addr, resp)
        return resp

    def function_headers(self) -> dict:
        """
        Get all function headers in the binary.

        Returns a dict mapping rebased address (as string) to:
            - name: Function name
            - size: Function size
        """
        # Return cached if available
        if self.cache._function_headers is not None:
            return self.cache._function_headers

        resp = {}
        try:
            for addr, func in self.deci.functions.items():
                # Skip library functions if possible
                name = func.name
                if not name:
                    continue

                name = str(name)
                # Skip PLT/GOT functions
                if name.startswith(".") or "@" in name:
                    continue

                rebased_addr = str(int(self.rebase_addr(addr, down=True)))
                resp[rebased_addr] = {
                    "name": name,
                    "size": int(func.size) if func.size else 0
                }
        except Exception as e:
            print(f"[decomp2dbg] function_headers failed: {e}")

        self.cache._function_headers = resp
        return resp

    def global_vars(self) -> dict:
        """
        Get all global variables in the binary.

        Returns a dict mapping rebased address (as string) to:
            - name: Variable name
        """
        # Return cached if available
        if self.cache._global_vars is not None:
            return self.cache._global_vars

        resp = {}
        try:
            for addr, gvar in self.deci.global_vars.items():
                name = gvar.name
                if not name:
                    continue

                rebased_addr = str(int(self.rebase_addr(addr, down=True)))
                resp[rebased_addr] = {
                    "name": str(name)
                }
        except Exception as e:
            print(f"[decomp2dbg] global_vars failed: {e}")

        self.cache._global_vars = resp
        return resp

    def structs(self) -> dict:
        """
        Get all struct definitions.

        Returns a dict mapping struct name to:
            - name: Struct name
            - members: List of member dicts with name, type, size
        """
        # Return cached if available
        if self.cache._structs is not None:
            return self.cache._structs

        resp = {}
        try:
            for name, struct in self.deci.structs.items():
                struct_info = {
                    "name": str(name),
                    "members": []
                }

                if struct.members:
                    for offset, member in struct.members.items():
                        member_info = {
                            "name": str(member.name) if member.name else "",
                            "type": str(member.type) if member.type else "",
                            "size": int(member.size) if member.size else 0,
                            "offset": int(offset)
                        }
                        struct_info["members"].append(member_info)

                resp[str(name)] = struct_info
        except Exception as e:
            print(f"[decomp2dbg] structs failed: {e}")

        self.cache._structs = resp
        return resp

    def breakpoints(self) -> dict:
        """Get breakpoints (not implemented - returns empty dict)."""
        return {}

    def binary_path(self) -> str:
        """Get the filesystem path of the binary being decompiled."""
        try:
            return self.deci.binary_path or ""
        except Exception:
            return ""

    def versions(self) -> dict:
        """Get version information about the decompiler environment."""
        resp = {
            "name": self.deci.name,
            "version": "unknown",
            "python": sys.version,
        }

        # Try to get decompiler-specific version info
        try:
            if self.deci.name == "ida":
                import idaapi
                resp["version"] = idaapi.get_kernel_version()
                if idaapi.init_hexrays_plugin():
                    resp["hexrays"] = idaapi.get_hexrays_version()
            elif self.deci.name == "binja":
                import binaryninja
                resp["version"] = binaryninja.core_version()
            elif self.deci.name == "angr":
                import angr
                resp["version"] = angr.__version__
            elif self.deci.name == "ghidra":
                resp["version"] = "pyhidra"
        except Exception:
            pass

        return resp

    def focus_address(self, addr: int) -> bool:
        """
        Focus the given address in the decompiler GUI.

        Returns True if successful, False otherwise.
        """
        try:
            addr = self.rebase_addr(addr)
            self.deci.gui_goto(addr)
            return True
        except Exception:
            return False

    def ping(self) -> bool:
        """Check if the server is alive."""
        return True

    #
    # XML-RPC Server
    #

    def start_xmlrpc_server(self, host: str = None, port: int = None):
        """
        Start the XML-RPC server.

        Args:
            host: Host address (defaults to self.host)
            port: Port number (defaults to self.port)
        """
        host = host or self.host
        port = port or self.port

        print(f"[+] Starting XMLRPC server: {host}:{port}")
        server = SimpleXMLRPCServer(
            (host, port),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        server.register_introspection_functions()
        server.register_function(self.decompile)
        server.register_function(self.function_headers)
        server.register_function(self.function_data)
        server.register_function(self.global_vars)
        server.register_function(self.structs)
        server.register_function(self.breakpoints)
        server.register_function(self.binary_path)
        server.register_function(self.versions)
        server.register_function(self.focus_address)
        server.register_function(self.ping)
        print("[+] Registered decompilation server!")
        while True:
            server.handle_request()
