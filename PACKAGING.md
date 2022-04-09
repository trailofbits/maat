# Packaging

This is a reference for our current packaging and Continuous Delivery workflow

## Python module packaging

We provide python wheel packages for Maat's python extension module. The current target platforms are **x86_64 linux** and **x86_64**/**arm64** **macOS**, and we support Python **3.7** to **3.10**.

Python packages are built and uploaded to PyPI using Github Actions. The corresponding workflow file is [python-package.yml](.github/python-package.yml). It uses the [`cibuildwheel`](https://cibuildwheel.readthedocs.io/en/stable/) tool to build wheels automatically in the CI/CD environment.

The python module configuration files are found in [bindings/packaging/](./bindings/packaging/). `setup.py` uses the [`cmake-build-extension`](https://github.com/diegoferigo/cmake-build-extension) package in order to build the python module.

### CMake config for packaging

Packaging Maat's python module we need to set the `maat_PYTHON_PACKAGING` CMake variable. This allows to build only the python extension module, to install Maat in the expected wheel location, and to install only necessary files (no dev headers, no CMake config files).

We also set `maat_USE_EXTERNAL_SLEIGH` to `OFF` so that we build and embed a compatible version of sleigh.

### Build environment

`cibuildwheel` builds the macOS wheels directly on the CI/CD macOS container. However to
build linux wheels that are compatible with many linux distributions, `cibuildwheel` uses `manylinux`
docker images. This has drawbacks:

- `manylinux` support for modern build tools is bad (C++17, C++11 mangling ABI)
- most dependencies don't have an SDK compatible with `manylinux` (z3, sleigh, LIEF)

To address this issue, we provide our own custom `manylinux` image, on which we've built all dependencies to ensure `manylinux` compatibility. The image is stored on the `ghcr.io` container registry and pulled by the packaging workflow. For reference, the image is generated from this [Dockerfile](bindings/packaging/Dockerfile).

### Building arm64 macOS wheels

In order to support new M1-based computers we need to build wheels for arm64 on macOS. To do so we cross-compile Maat and all its dependencies to `arm64` on a `x86_64` host. Cross-compiling is done directly in the CI/CD runner and the steps can be found in the `python-packaging.yml` workflow file.

Although all dependencies are cross-compiled, we still need to run the `x86_64` sleigh compiler to generate the processor spec files. Maat's CMake build thus supports a `maat_SLEIGH_COMPILER` cache variable that can be overwritten so that it uses the correct `x86_64` sleigh compiler binary and not the `arm64` one.

