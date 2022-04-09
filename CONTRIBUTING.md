# Contributing

**Last updated**: 09/04/2022

- [General guidelines](#general-guidelines)
- [Supporting a new architecture](#support-new-arch)
- [Supporting a new environment/OS](#support-new-os)
- [Writing tests](#writing-tests)

## General guidelines

First of all, thank you for being interested in contributing to Maat! Here are the general steps to follow:

- clone Maat's repository on your development machine
- follow instructions in [HACKING.md](./HACKING.md) to build and test Maat in developer mode
- create a new branch and implement your feature in it. You should base your branch on `master` for bug fixes and on `dev-next` for new features  
- create a pull request for your branch

If you're wondering whether a given feature is worth implementing, or if you're unsure about how it should be integrated in the existing code-base, feel free to [open a discussion](https://github.com/trailofbits/maat/discussions) on our Github so that we can talk about it beforehand.

Similarly, if you're forking on a new feature and questions arise before it is ready for review, don't hesitate to open a _draft_ pull request for it. We'll use it to answer questions you might have, give traceable feedback, and make code comments and suggestions.


## <a name="support-new-arch"></a> Supporting a new architecture

If you're interested in adding an interface for a new architecture in Maat, here are some pointers and general steps to follow. (Please note that here we're talking about adding architectures that are _already supported by Ghidra_ to Maat, not writing a specification for an all new architecture).

This guide takes the example of the `X86` architecture.

### 1. Specifying the new architecture

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

Also don't forget to register the new architecture by adding the appropriate line in
`bindings/python/py_arch.cpp` so that the architecture becomes available in Python bindings
in the `ARCH` enumeration.

### 2. Integrating the new architecture

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


### 3. Writing the register translator

To finish integrating the new architecture in Maat, you have to declare a new register translator function in `src/include/maat/sleigh_interface.hpp`.  It is a function that takes a register name (as defined by Ghidra's processor specification files), and returns the corresponding Maat register. For example for X86 we have:

```
maat::ir::Param sleigh_reg_translate_X86(const std::string& reg_name);
```

Then implement the function in `src/third-party/sleigh/native/reg_translator.cpp`:

```
maat::ir::Param sleigh_reg_translate_X86(const std::string& reg_name)
{
    if (reg_name == "AL") return maat::ir::Reg(maat::X86::EAX, 7, 0);
    if (reg_name == "AH") return maat::ir::Reg(maat::X86::EAX, 15, 8);
    ...
}
```

Finally, update the `reg_name_to_maat_reg()` function in `src/third-party/sleigh/native/sleigh_interface.cpp` to make it call your register translator function for the new architecture.

### 4. Write tests

After the new architecture is implemented, we recommend to add some unit tests to check that
instructions are properly emulated. This will help catch various errors that might have gone
under the radar during implementation.

Unitary tests live in the `tests/unit-tests/` folder. You can create a new test file (e.g `test_archX86.cpp`) in this folder with a method that run all tests we want on the architecture (e.g `void test_archX86();`). For guidance on how we write tests, checkout the [Writing tests](#writing-tests) section.

What we usually do is writing a small dedicated test function for each assembly instruction we want to test. This test function runs the instruction with given inputs and checks that
the outputs (CPU & memory changed) are correct w.r.t the instruction semantics. It can run
the instruction several times on different inputs, or several variants of the instruction
(for instance switching between register, immediate, and memory operands).

For a model of how to write unit-tests for an architecture, you can check out the tests we wrote for X64 in `tests/unit-tests/test_archX64.cpp`. **Please read the following important information before writing any arch testing code**:

- at the time of writing, we only have testing code for X86 and X64. The arch testing code is huge and for the most part consists in old legacy code. It has undergone several API changes and thus can contain some awkward coding patterns, many of whom would require too much time to be rewritten. When writing tests for a new architecture, please feel free to come up with your own cleaner testing code and patterns

- we've written a lot of tests for X86 and X64. That was very useful for early testing, but for new architecture there's no need to write tests for every single instruction! To some extend we can trust Ghidra's lifting. We recommend to write tests for a subset of the most common instructions, branching instructions, some conditional instructions, and for behaviours that are very arch specific (for example switching between ARM/THUMB on 32-bits ARM)

### 5. (Optional) Handle unsupported instructions

Using Ghidra's sleigh to lift instructions is great. However, there are some instructions whose semantics can not be described in their IR, _p-code_. The most obvious examples would the `syscall` or `cpuid` Intel instructions. For unsupported instructions, sleigh will emit a special _p-code_ operation: 

```
CALLOTHER <NUM>
```

`CALLOTHER` means "I can't model this instruction, please do it yourself using a callback". `NUM` uniquely identifies the unsupported instruction for which this `CALLOTHER` has been emitted.

It is possible to add callbacks in Maat to execute `CALLOTHER` IR instructions. To do so, following the instructions below:

1. Add a unique identifier for an unsupported instruction to the `Id` enum in `src/include/maat/callother.hpp`, e.g `Id::X64_SYSCAL`
2. Update the `mnemonic_to_id()` function in `src/engine/callother.cpp`. This function takes an architecture and a mnemonic and returns the correspondign `Id` value (for `Arch::Type::X64` and `"SYSCALL"` it would return `Id::X64_SYSCALL`). This function is used by the sleigh interface when generating _p-code_
3. Write an emulation callback for the unsupported instruction in `src/engine/callother.cpp` 
4. Don't forget to update the `default_handler_map()` function with the new instruction and handler

**Note**: depending on the instruction complexity it can be pretty touchy to correctly implement the emulation callback. Moreover, writing a `CALLOTHER` callback often requires using the internals, which can be tricky at first. Don't hesitate to reach out to a maintainer for guidance!


## <a name="support-new-os"></a> Supporting a new environment / operating system

### 1. Adding a new environment emulator

Maat has the possibility to emulate to some extend the environment in which a process is running. It has a built-in `EnvEmulator` class defined in `src/include/maat/env/env.hpp`. The
default `EnvEmulator` has the following essential information:

- a simple symbolic filesystem 
- default ABIs to use for function calls and system calls
- a map of syscall numbers to callback functions used to emulated system calls

To add support for an new environment in Maat, you can simply create an emulator that inherits from `EnvEmulator`. For instance, we implemented `LinuxEmulator` defined in
`src/include/maat/env/env.hpp` and implemented in `src/env/env_linux.cpp`.

It is also possible to extend an existing environment implementation to support a new architecture. For instance, adding ARM support for the existing `LinuxEmulator`.

### 2. Adding new function call ABIs

When implementing a new environment, you'll likely need to specify one or several calling conventions for functions and syscalls.

Start by adding the new ABI in the `maat::env::abi::Type` enum defined in `src/include/maat/env/library.hpp`. Then create a class that inherits from the `ABI` class and implements the
required methods to get/set arguments, return values, etc.

Note that ABI classes are intended to be used following a [singleton pattern](https://stackoverflow.com/questions/1008019/c-singleton-design-pattern) and need to implement the `static const ABI& instance();` method.

Once the ABI class is implemented in `src/env/abi.cpp`, don't forget to update the `_get_default_abi()` and `_get_syscall_abi()` methods in `src/env/env.cpp` to return the new ABI for the relevant architecture/OS combination.


### 3. Supporting system calls

Once you created a new environment and added new ABIs, you can write custom callbacks to emulate system calls on this environment. A syscall callback must have the following prototype:

```
FunctionCallback::return_t my_callback(
    MaatEngine& engine,
    const std::vector<Value>& args
)
```

It takes a reference to the `MaatEngine` that is executing the syscall, and a list of values for the syscall parameters. Thanks to the `ABI` class added earlier, Maat will automatically resolve the parameter values and seemlessly pass them to the callback. This way we abstract the underlying architecture from the callback, and only need to change the ABI to make the
callback work for another architecture.

The callback returns a `FunctionCallback::return_t` which is defined as a `std::variant<>` and can be either:

- nothing (`std::monostate`)
- a concrete integer value
- a `Value` instance (which can hold symbolic data)

For examples of implemented system calls, check out `src/env/emulated_syscalls/linux_syscalls.cpp`.

Finally, after implementing syscall callbacks, make sure to add them to the new environment.
For example, for Linux we're doing it as a mapping `{syscall_num:callback_function}`. We have a helper function `syscall_func_map_t linux_x86_syscall_map()` implemented in `src/env/emulated_syscalls/linux_syscalls.cpp` and defined in `src/include/maat/env/syscalls.hpp` that
generates the syscall map and that is called from `LinuxEmulator`'s constructor.


## Writing tests

### Native tests
Native tests are where 99% of Maat's testing is done. There are two types of native tests:

- unitary tests: they test basic low-level functionalities of the framework. The test files live in the `tests/unit-tests/` folder
- advanced tests: they test Maat's API globally, often using Maat to perform some symbolic analysis on small programs and crackmes. They can be found in `tests/adv-tests`

For each type of tests, there's a `test_all.cpp` file with a `main()` function that calls other test functions defined in the other test files.

Both tests are compiled as test binaries named `unit-tests` and `adv-tests` respectively. Run the binaries to run the tests. If tests are successful, the binaries exit properly. If any test fails, it will raise a `maat::test_exception()` with an error message, which will abort the test binary and display the error message.

For examples of how to write tests, just take a look at the existing tests in `tests/unit-tests/`.

### Python tests
Python tests are using `pytest` and are written using Maat's Python API. They are used only for two things:

- verify that we didn't introduce breaking changes in the Python bindings
- serve as implicit reference scripts for how to use the Python bindings

Python tests mostly consist in crackmes, challenges, and small programs, on which we run advanced symbolic analysis. They are the Python counterpart of the native _advanced tests_ we mentioned above. 

No-goals of Python tests include:

- unit-testing of bindings implementation
- unit-testing of Maat functionalities
