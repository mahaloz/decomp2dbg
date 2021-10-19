# decomp2gef
A plugin to introduce a generic API for Decompiler support in GEF. Like GEF, the plugin
is battery-included and requires no external dependencies other than Python. 

![decomp2gef](decomp2gef.png)
[Demo viewable here.](https://asciinema.org/a/442740)

## Quick Start
First, install the decomp2gef plugin into gef:
```bash
cp decomp2gef.py ~/.decomp2gef.py && echo "source ~/.decomp2gef.py" >> ~/.gdbinit
```
Alternatively, you can load it for one-time-use inside gdb with:
```bash 
source /path/to/decomp2gef.py
```

Now import the relevant script for you decompiler:

### IDA
- open IDA on your binary and press Alt-F7
- popup "Run Script" will appear, load the `decomp2gef_ida.py` script from this repo

Now use the `decompiler connect` command in GDB. Note: you must be in a current session
of debugging something.

## Usage 
In gdb, run:
```bash
decompiler connect ida
```

If all is well, you should see:
```bash
[+] Connected to decompiler!
```

Now just use GEF like normal and enjoy decompilation and decompiler symbol mapping!
When you change a symbol in ida, like a function name, if will be automatically reflected in 
gdb after just 2 steps!

## Features 
- [X] Auto-updating decompilation context view
- [X] Auto-syncing function names
- [X] Breakable/Inspectable symbols
- [ ] Auto-syncing stack variable names
- [ ] Auto-syncing structs

## Abstract
The reverse engineering process often involves a decompiler making it fundamental to
support in a debugger since context switching knowledge between the two is hard. Decompilers
have a lot in common. During the reversing process there are reverse engineering artifacts (REA).
These REAs are common across all decompilers:
- stack variables
- global variables
- structs
- enums
- function headers (name and prototype)
- comments

Knowledge of REAs can be used to do lots of things, like [sync REAs across decompilers](https://github.com/angr/binsync) or
create a common interface for a debugger to display decompilation information. GEF is currently
one of the best gdb upgrades making it a perfect place to first implement this idea. In the future,
it should be easily transferable to any debugger supporting python3.

## Adding your decompiler

To add your decompiler, simply make a Python XMLRPC server that implements the 4 server functions
found in the `decomp2gef` Decompiler class. Follow the code for how to return correct types.
