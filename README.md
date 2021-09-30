# decomp2gef
A plugin to introduce a generic API for Decompiler support in GEF

## Installation
### IDA
- open IDA on your binary and press Alt-F7
- popup "Run Script" will appear, load the `decomp2gef_ida.py` script from this repo

## Usage 
In gdb, run:
```bash
source ./decomp2gef.py
```

Now connect to the decompiler
```bash
gef➤  decompiler connect
[+] Connected! 
```

Now just use GEF like normal :)

## Decompiler Commands
- `decompiler global_info import`:
    - imports global info like symbols, structs, and enums. Use this for function names as well.
    
- `decompiler global_info status`:
    - shows you status info of imported symbols

## Abstract
The reverse engineering process often involves a decompiler, making it fundamental to
support in a debugger, since context switching knowledge between the two is hard. Decompilers
have a lot in common. During the reversing process, there are reverse engineering artifacts (REA).
These REAs are common across all decompilers:
- stack variables
- global variables
- structs
- enums
- function headers (name and prototype)
- comments

Knowledge of REAs can be used to lots of things, like [sync REAs](https://github.com/angr/binsync) or
create a common interface for a debugger to display decompilation information. GEF is currently
one of the best gdb upgrades and makes for a perfect place to first implement this idea. In the future,
it should be easily transferable to any debugger supporting python3.

## Features
- [X] Decompilation view
- [X] Break on decompiler function symbols
- [ ] Resolve stack variable symbols in a function
- [ ] Decompilation caching
- [ ] Highlight current gdb line