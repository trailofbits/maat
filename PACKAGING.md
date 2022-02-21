# Packaging

This is a reference for our current packaging and Continuous Delivery workflow

## Python module packaging

We provide python wheel packages for Maat's python extension module. The current target platforms are **linux** and **macOS**, and we support Python **3.7** to **3.10**.

Python packages are built and uploaded to PyPI using Github Actions. The corresponding workflow file is [python-package.yml](.github/python-package.yml). It uses the `cibuildwheel` tool to build wheels automatically in the CI/CD environment.

The python module configuration files are found in [bindings/packaging/](./bindings/packaging/). `setup.py` uses the `cmake-build-extension` package in order to build the python module.

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
