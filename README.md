# decomp2gef
A plugin to introduce a generic API for decompiler usage and syncing in GDB with the 
help of the [GEF](https://github.com/hugsy/gef) plugin.

![decomp2gef](./assets/decomp2gef.png)
[Demo viewable here.](https://asciinema.org/a/442740)

## Install (script/fast)
The easiest and fastest way to install is using the `install.sh` script!
```bash
./install.sh --ida /path/to/ida/plugins
```

Make sure to define the correct option for your decompiler of choice. Use `--help` for more info!

## Install (manual)
If you can't use the script (non-WSL Windows install for the decompiler), follow the steps below: 

If you only need the decompiler side of things, copy the associated decompiler plugin to the
decompiler's plugin folder. Here is how you do it in IDA:

Copy all the files in `./decompilers/d2g_ida/` into your ida `plugins` folder:
```bash
cp -r ./decompilers/d2g_ida/* /path/to/ida/plugins/
```

If you also need to install the gdb side of things, use the line below: 
```bash
pip3 install . && \
cp decomp2gef.py ~/.decomp2gef.py && echo "source ~/.decomp2gef.py" >> ~/.gdbinit
```

## Simpler Install

If you are looking for a no-dependencies plugin, you can use the old
[simple_install](https://github.com/mahaloz/decomp2gef/tree/simple_install) branch which is
simpler to install, but has fewer features. 

## Usage 
First, start the decompilation server on your decompiler. This can be done by using the hotkey `Ctrl-Shift-D`,
or selecting the `decomp2GEF: configure` tab in your associated plugins tab. After starting the server, you should
see message in your decompiler
```
[+] Starting XMLRPC server: localhost:3662
[+] Registered decompilation server!
```

Next, in gdb, run:
```bash
decompiler connect <decompiler_name>
```

If you are running the decompiler on a VM or different machine, you can optionally provide the host and 
port to connect to. Here is an example:
```bash
decompiler connect ida 10.211.55.2 3662
```

First connection can take up to 30 seconds to register depending on the amount of globals in the binary.
If all is well, you should see:
```bash
[+] Connected to decompiler!
```

### Decompilation View
On each breakpoint event, you will now see decompilation printed, and the line you are on associated with
the break address. 

### Functions and Global Vars
Functions and Global Vars from your decompilation are now mapped into your GDB like normal Source-level 
symbols. This means normal GDB commands like printing and examination are native:
```bash
b sub_46340
x/10i sub_46340
```
```bash
p dword_267A2C 
x dword_267A2C
```

### Stack Variables and Function Args
Some variables that are stored locally in a function are stack variables. For the vars that can be mapped
to the stack, we import them as convenience variables. You can see their contents like a normal GDB convenience
variable:
```bash 
p $v4
```

Stack variables will always store their address on the stack. To see what value is actually in that stack variable,
simply dereference the variable:
```bash
x $v4
```

This also works with function arguments if applicable (mileage may vary):
```bash
p $a1
```

Note: `$v4` in this case will only be mapped for as long as you are in the same function. Once you leave the function
it may be unmapped or remapped to another value.

## Features 
- [X] Auto-updating decompilation context view
- [X] Auto-syncing function names
- [X] Breakable/Inspectable symbols
- [X] Auto-syncing stack variable names
- [ ] Auto-syncing structs

## Abstract
The reverse engineering process often involves a decompiler, making it fundamental to
support in a debugger since context switching knowledge between the two is hard. Decompilers
have a lot in common. During the reversing process there are reverse engineering artifacts (REA).
These REAs are common across all decompilers:
- stack variables
- global variables
- structs
- enums
- function headers (name, ret type, args)
- comments

Knowledge of REAs can be used to do lots of things, like [sync REAs across decompilers](https://github.com/angr/binsync) or
create a common interface for a debugger to display decompilation information. GEF is currently
one of the best gdb upgrades making it a perfect place to first implement this idea. In the future,
it should be easily transferable to any debugger supporting python3.
