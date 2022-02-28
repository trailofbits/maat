# Contributing

Here are some guidelines that will help you contribute to Maat.

## General guidelines

Here are the main steps to follow to contribute to Maat:

- clone Maat's repository on your development machine
- follow instructions in [HACKING.md](./HACKING.md) to build and test Maat in developer mode
- create a new branch and implement your feature in it
- create a pull request for your branch

If you're wondering whether a given feature is worth implementing, or if you're unsure about how it should be integrated in the existing code-base, feel free to [open a discussion](https://github.com/trailofbits/maat/discussions) on our Github so that we can talk about it beforehand.

Similarly, if you're forking on a new feature and questions arise before the it is ready, make sure to open a _draft_ pull request for it. We'll use it to answer questions you might have, give traceable feedback, and make code comments and suggestions.


## Adding support for a new architecture

If you're interested in adding an interface for a new architecture in Maat, here are some pointers and general steps to follow. (Please note that here we're talking about adding architectures that are _already supported by Ghidra_ to Maat, not writing a specification for an all new architecture).

This guide takes the example of the `X86` architecture.

### Specifying the new architecture

The first step is to add the architecture definition in `src/include/maat/arch.hpp`.

You'll need to add the architecture to the `Arch::Type` enum (e.g `Arch::Type::X86`), and add
corresponding CPU mode(s) to the `CPUMode` enum (e.g `CPUMode::X86`).

Then, create a new namespace for the architecture which will contain unique identifiers for the architecture CPU registers, and a specialisation of the generic `Arch` class:

```
/// Namespace for X86-32 specific definitions and classes
namespace X86
{
    /* Registers */
    static constexpr reg_t EAX = 0; ///< General purpose register
    static constexpr reg_t EBX = 1; ///< General purpose register
    ...
    static constexpr reg_t NB_REGS = 69;

    class ArchX86: public Arch
    {
        ...
    };
}
```

Finally you can implement the `Arch` subclass (e.g `ArchX86`) in the `src/arch/` folder. Look at other archs implemented in `src/arch` and do something similar. There are only a few methods to implement such as:

- generic getters for stack and program counter registers
- getting the size of a register
- register <-> register string translation (e.g `maat::X86::EAX` <-> `"eax"`)

Once the architecture is implemented, don't forget to add the corresponding file in the
source files list in the top-level [CMakeLists.txt](./CMakeLists.txt).

### Integrate the new architecture

Now that the new architecture is specified, we need to integrate it in various places
in the source code.

First of all, update the `MaatEngine::MaatEngine()` constructor in `src/engine/engine.cpp`
to handle the new architecture.

Then, update the `Lifter::Lifter()` constructor in `src/arch/lifter.cpp`. The only thing you need to do is point it to the Ghidra sleigh specification files (`.sla` & `.pspec`) for the architecture you're adding. Tip: browse [Ghidra's processor list](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors) to find out the spec files names to use.

Last but not least, explicitly add the required sleigh specification files as targets in the top-level [CMakeLists.txt](./CMakeLists.txt). Use the `maat_sleigh_compile()` macro which takes two arguments:

- the directory withing [Ghidra's processor list](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Processors) which corresponds to the architecture (e.g `x86/`)
- the prefix name for the `.sla` and `.pspec` files (should be the same prefix, if not then
please report it to use)

For example for X86 and X64 you would add:
````
maat_sleigh_compile(x86 x86-64)
maat_sleigh_compile(x86 x86)
````

### Write Translator in sleigh_interface
TODO

### Environment/ABI
TODO

### Callother
TODO

### Write tests
TODO