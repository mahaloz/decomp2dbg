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

## Features
- [X] decompilation view
- [ ] Break on decompiler function symbols
- [ ] Resolve stack variable symbols in a function
- [ ] Decompilation caching
- [ ] Highlight current gdb line