# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

decomp2dbg is a symbol syncing framework that bridges decompilers (IDA Pro, Binary Ninja, Ghidra, angr-management) with GDB debuggers. It enables reversers to use symbols and decompiled code from their decompiler directly within GDB via XML-RPC communication.

## Build and Installation

```bash
# Development install
pip install -e .

# Production build
python -m build

# Install decompiler plugins (interactive installer)
pip install decomp2dbg && decomp2dbg --install

# Manual GDB setup: copy d2d_client.py and add to .gdbinit
cp decomp2dbg/d2d_client.py ~/.d2d_client.py && echo "source ~/.d2d_client.py" >> ~/.gdbinit
```

**Key Components:**

- `decompilers/server_template.py` - Base XML-RPC interface all decompiler plugins implement
- `decomp2dbg/clients/client.py` - Base DecompilerClient with XML-RPC connection logic
- `decomp2dbg/clients/gdb/gdb_client.py` - Main GDB client, command interface, symbol syncing
- `decomp2dbg/clients/gdb/symbol_mapper.py` - Native GDB symbols via ELF manipulation (Linux only, requires gcc/objcopy)
- `decomp2dbg/clients/gdb/decompiler_pane.py` - Decompilation display in GEF/pwndbg context
- `d2d.py` - GDB entry point, auto-detects GDB variant (vanilla/GEF/pwndbg)

## GDB Commands

When connected via `decompiler connect [host] [port]`:
- `decompiler connect` - Connect to decompiler server
- `decompiler disconnect` - Disconnect from server
- `decompiler info` - Show connection status
- Symbol syncing and decompilation pane updates happen automatically on breakpoints

## Important Patterns

- **Decorators**: `@only_if_connected`, `@only_if_gdb_running` guard methods requiring active connections
- **PIE/ASLR rebasing**: GDB client rebases addresses for position-independent executables
- **Convenience variables**: Local/stack variables available as GDB vars (`$v4`, `$a1`, etc.)
- **Factory pattern**: `d2d.py` detects GDB variant and instantiates appropriate client class

## Dependencies

- Core: `sortedcontainers`, `pyelftools`, `declib>=4.0.1`
- External tools (Linux native symbols): `gcc`, `objcopy`
- Environment: `NO_COLOR` env var disables terminal colors
