# decomp2gef
A plugin to introduce a generic API for decompiler usage and syncing in GDB with the 
help of the [GEF](https://github.com/hugsy/gef) plugin.

![decomp2gef](./assets/decomp2gef.png)
[Demo viewable here.](https://asciinema.org/a/442740)

## Installing
First, install decomp2gef deps with pip:
```bash
pip3 install decomp2gef
```

Next, install the decomp2gef plugin into GEF:
```bash
cp decomp2gef.py ~/.decomp2gef.py && echo "source ~/.decomp2gef.py" >> ~/.gdbinit
```

Finally, install the plugin into your decompiler of choice using the files in `./decompiler`.
### IDA
Copy all the files in `./decompilers/d2g_ida/` into your ida `plugins` folder:
```
cp -r ./decompilers/d2g_ida/* /path/to/ida/plugins/
```

If you are looking for a no-dependencies plugin, you can use the old
[simple_install](https://github.com/mahaloz/decomp2gef/tree/simple_install) branch which is
simpler to install, but has fewer features. 

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
