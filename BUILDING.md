# Building & installing with CMake

## Build

The default build includes the Python bindings and requires CMake 3.26 or later. For a C++-only build with an installed Sleigh, CMake 3.18 or later is sufficient.

* [zlib](https://zlib.net/) - for loading compressed Sleigh processor specifications
* [GMP](https://gmplib.org/) - `libgmp` for big-sized arithmetic
* [Z3](https://github.com/Z3Prover/z3) - for constraint solving
  * Can be disabled with CMake option `-Dmaat_USE_Z3=OFF` during configuration
* [LIEF](https://github.com/lief-project/LIEF) 1.0 - for automatic binary loading
  * Can be disabled with CMake option `-Dmaat_USE_LIEF=OFF` during configuration
* [sleigh](https://github.com/lifting-bits/sleigh) 12.2 - for Ghidra sleigh pcode handling
  * To build the bundled Sleigh, use CMake 3.25 or later, run `git submodule update --init --recursive`, and configure with `-Dmaat_USE_EXTERNAL_SLEIGH=OFF`.
* GIL-enabled CPython 3.10 or newer development headers for the stable ABI Python bindings
  * Bindings can be skipped with CMake option `-Dmaat_BUILD_PYTHON_BINDINGS=OFF` during configuration

You can use our [Dockerfile](Dockerfile) as a reference for how to download and install dependencies. Note that if building the Dockerfile, it uses a submodule'd [sleigh project](https://github.com/lifting-bits/sleigh), so you must either clone Maat with `git clone --recursive ...` or run `git submodule update --init --recursive` after cloning before building the Docker image.

Assuming the above are installed into a system location (where CMake will automatically find them), here are the steps for building in release mode with a single-configuration generator, like the Unix Makefiles one:

```sh
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
cmake --build build
```

Here are the steps for building in release mode with a multi-configuration
generator, like the Visual Studio ones:

```sh
cmake -S . -B build
cmake --build build --config Release
```

If dependencies are installed under a custom prefix, pass `-DCMAKE_PREFIX_PATH=<prefix>` when configuring, or use a [package-specific hint][1]. On macOS or Linux, if the runtime loader cannot find a shared dependency such as LIEF after installation, configure Maat with `-DCMAKE_INSTALL_RPATH=<prefix>/lib` and reinstall.

## Install

This project doesn't require any special command-line flags to install to keep
things simple. As a prerequisite, the project has to be built with the above
commands already.

Here is the command for installing the release mode artifacts with a
single-configuration generator, like the Unix Makefiles one:

```sh
cmake --install build
```

Here is the command for installing the release mode artifacts with a
multi-configuration generator, like the Visual Studio ones:

```sh
cmake --install build --config Release
```

### Python bindings

The Python extension and its processor files install under the CMake install
prefix using the selected interpreter’s platform-specific package layout
(for example, `lib/python3.11/site-packages`). To install into a virtual
environment, activate it before configuring and use it as the install prefix:

```sh
cmake -S . -B build "-DPython3_EXECUTABLE=$VIRTUAL_ENV/bin/python"
cmake --build build
cmake --install build --prefix "$VIRTUAL_ENV"
```

Packagers can override the layout with `-Dmaat_INSTALL_PYTHONMODULEDIR=<relative-path>`.

[1]: https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure
