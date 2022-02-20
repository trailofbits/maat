# Packaging

This is a reference for our current packaging and Continuous Delivery workflow

## Python module packaging

We provide packages for Maat's python extension module. The current target platforms are **linux** and **macOS**, and we support Python **3.7** to **3.10**. The packages are built as
python wheels.

To build and release python packages we use Github Actions. The corresponding workflow file is [python-package.yml](.github/python-package.yml). It uses the `cibuildwheel` package to build wheels automatically.

The python project configuration files are found in [bindings/packaging/](./bindings/packaging/). `setup.py` uses the `cmake-build-extension` package in order to build the python module.

### CMake config for packaging

When building Maat for python packaging we need to set the `maat_PYTHON_PACKAGING` CMake variable. This allows to build only the python extension module, to install Maat in the expected wheel location, and to install only necessary files (no dev headers, no CMake config files).

We also set `maat_USE_EXTERNAL_SLEIGH` to `OFF` so that we build and embed a compatible
version of sleigh in the extension module.

### Build environment

`cibuildwheel` can build the macOS wheels directly on the CI/CD macOS container. However to
build linux wheels that are compatible with many linux distributions it relies on `manylinux`
docker images. This has drawbacks:

- `manylinux` support for modern build tools is bad (C++17, C++11 mangling ABI)
- some dependencies don't have packages compatible with `manylinux` (z3, sleigh, LIEF)

To address this issue, we provide our own custom `manylinux` image, on which we've built all dependencies to ensure `manylinux` compatibility. The image is stored on trailofbit's `ghcr.io` container registry. It is generated from this [Dockerfile](bindings/packaging/Dockerfile). 

*Note:* packaging prebuilt dependencies for linux makes installation easier but results in bigger python wheels.