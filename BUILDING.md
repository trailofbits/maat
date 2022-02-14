# Building with CMake

## Build

This project requires a few dependencies:

* [GMP](https://gmplib.org/) - `libgmp` for big-sized arithmetic
* [Z3](https://github.com/Z3Prover/z3) - for constraint solving
  * Can be disabled with CMake option `-Dmaat_USE_Z3=OFF` during configuration
* [LIEF](https://github.com/lief-project/LIEF) - for automatic binary loading
  * Can be disabled with CMake option `-Dmaat_USE_LIEF=OFF` during configuration
* [sleigh](https://github.com/lifting-bits/sleigh) - for Ghidra sleigh pcode handling
  * Vendored version can be built with CMake option `-Dmaat_USE_EXTERNAL_SLEIGH=OFF` during configuration after you pull the submodule (`git submodule update --init --recursive`)
* Python3 development headers and library - for Python bindings
  * Bindings can be skipped with CMake option `-Dmaat_BUILD_PYTHON_BINDINGS=OFF` during configuration

You can use our [Dockerfile](Dockerfile) as a reference for how to download and install dependencies.

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

If the dependencies are installed into a non-system/default directory, then you can [pass hints to CMake][1] on where to find the respective packages (something like `-D<PackageName>_DIR` or `-D<PackageName>_ROOT` depending on what/how the package was installed; see the package's documentation on how to correctly use it with CMake).

## Install

This project doesn't require any special command-line flags to install to keep
things simple. As a prerequisite, the project has to be built with the above
commands already.

The below commands require at least CMake 3.15 to run, because that is the
version in which [Install a Project][2] was added.

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

### Python Module

To install the Python module, make sure that you configured the project with the option `-Dmaat_BUILD_PYTHON_BINDINGS=ON`, and install to the user site-packages location:

```sh
# If you're configuring outside a virtualenv
prefix="$(python3 -m site --user-site)"
# If you're configuring inside a virtualenv
prefix="python3 -c 'import site; print(site.getusersitepackages())'"

cmake -S . -B build -Dmaat_INSTALL_PYTHONMODULEDIR="${prefix}" -Dmaat_BUILD_PYTHON_BINDINGS=ON
cmake --build build
cmake --install build
```

NOTE: CMake configuration and installation should both take place either inside or outside of the virtual environment or else the install path for the Python module could be incorrect (especially on macOS).

[1]: https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure
[2]: https://cmake.org/cmake/help/latest/manual/cmake.1.html#install-a-project
