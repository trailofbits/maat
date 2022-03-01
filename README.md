<p align="center" >
     <br><br>
<img width="45%" src="ressources/maat_logo.png"/> <br>
  <!-- TODO
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License: MIT"> &nbsp; &nbsp;
   <img src="https://img.shields.io/badge/Build-Linux-green" alt="Build: Linux">  &nbsp; &nbsp;
  <img src="https://img.shields.io/badge/Version-v0.2-green" alt="Version: 0.2"> &nbsp; &nbsp;
  <a href="http://maat.re"><img src="https://img.shields.io/badge/Website-maat.re-blue" alt="Website: maat.re"></a> -->
  <br>
  <br>
  <br>
</p>


# About

Maat is an open-source Dynamic Symbolic Execution and Binary Analysis framework. It provides various functionalities such as symbolic execution, taint analysis, constraint solving, binary loading, environment simulation, and leverages Ghidra's sleigh library for assembly lifting: https://maat.re

Key features:

- **Fast & Portable**: Designed to scale to real-world applications. Fully written in C++ for good runtime
                performance. There are hardly any runtime dependencies, and most of them are optional
- **User-friendly**: Maat has a flexible debugger-like API, and its features are configurable to
                      adapt to many different use-cases. As any self-respecting modern framework, it comes with *Python bindings*
- **Multi-arch**: With lifting and emulation based on Ghidra's awesome *sleigh* library, Maat
                      has the potential to emulate many architectures, including exotic ones

# Getting started
- [Installation](#installation)
- [Hacking](./HACKING.md)
- [Contributing](./CONTRIBUTING.md)
- [Tutorials](https://maat.re/tutorials.html)
     - [Getting started](https://maat.re/tutorials/get_started.html)
     - [Event hooking](https://maat.re/tutorials/events.html)
     - [Dynamic symbolic execution](https://maat.re/tutorials/dse.html)
- [Documentation](https://maat.re/python_api/index.html)
     - [Python API](https://maat.re/python_api/index.html)
     - [C++ API](https://maat.re/cpp_api/index.html)
- [Example](#example)
- [Contact](#contact)

# Installation

To install Maat's python module:
````
python3 -m pip install pymaat
````

To install Maat's native SDK and use the C++ API, check out [BUILDING.md](./BUILDING.md)

# Example

```Python
from maat import *

# Create a symbolic engine for Linux X86-32bits
engine = MaatEngine(ARCH.X86, OS.LINUX)

# Load a binary with one command line argument
engine.load("./some_binary", BIN.ELF32, args=[engine.vars.new_symbolic_buffer("some_arg", 20)])

# Get current eax value
engine.cpu.eax

# Read 4 bytes at the top of the stack
engine.mem.read(engine.cpu.esp, 4)

# Set a callback displaying every memory read
def show_mem_access(engine):
    mem_access = engine.info.mem_access
    print(f"Instruction at {engine.info.addr} reads {mem_access.size} bytes at {mem_access.addr}")

engine.hooks.add(EVENT.MEM_R, WHEN.BEFORE, callbacks=[show_mem_access])

# Take and restore snapshots
snap = engine.take_snapshot()
engine.restore_snapshot(snap)

# Run the binary
maat.run() 
```

# Contact
For general discussions, questions and suggestions, we use [Github Discussions](https://github.com/trailofbits/maat/discussions)

For reporting issues and bugs, please use [Github Issues](https://github.com/trailofbits/maat/issues)

For anything else, drop an e-mail at boyan.milanov@trailofbits.com
