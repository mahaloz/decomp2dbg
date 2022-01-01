# decomp2gef
A plugin to introduce a generic API for Decompiler support in GEF. Like GEF, the plugin
is battery-included and requires no external dependencies other than Python. 

[Demo viewable here.](https://asciinema.org/a/442740)

## Quick Start
This is the `simple_install` branch, which requires no python dependencies. You must
have Python3 installed as well as `objcopy` and `readelf` in your `$PATH`.

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