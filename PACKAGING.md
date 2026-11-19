# Building Python wheels

Maat ships as `pymaat` on PyPI and imports as `maat`. The [wheel workflow](.github/workflows/python-package.yml) builds standard CPython 3.10 through 3.15 wheels for Linux x86-64, macOS Intel, and macOS arm64. Each wheel contains the native extension and the processor files it loads at runtime.

## Build locally

Install GMP, Z3, and LIEF as described in [BUILDING.md](BUILDING.md), then run these commands from the repository root with uv installed.

```sh
git submodule update --init
uv build --wheel --python 3.13
uv venv --python 3.13 /tmp/pymaat-test
uv pip install --python /tmp/pymaat-test/bin/python dist/*.whl
/tmp/pymaat-test/bin/python -I -c 'from maat import ARCH, MaatEngine; MaatEngine(ARCH.X64)'
```

The local build uses the pinned Sleigh submodule. If Sleigh is already installed, pass `-Ccmake.define.maat_USE_EXTERNAL_SLEIGH=ON` to `uv build`. Set `CMAKE_PREFIX_PATH` for dependencies installed outside standard locations. The Python package version comes from Git tags.

## CI and releases

Every pull request builds, repairs, installs, and smoke-tests a CPython 3.13 wheel on each platform. Changes to the packaging configuration, workflow, dependency installer, or CMake install rules run all six Python versions. A manual **Python wheels** run also exercises the full matrix and saves the tested wheels as workflow artifacts.

Linux jobs load a local image built from public manylinux2014 with native dependencies installed. BuildKit reuses the image layers through the GitHub Actions cache. macOS jobs cache the installed dependencies by architecture, deployment target, toolchain, installer, and Sleigh revision. Pushes to `master` seed the caches and run the smoke builds. Fork pull requests can reuse the base branch caches and build from public sources on a miss. Release jobs build dependencies from scratch. Only a published GitHub release can start the PyPI trusted-publishing job, which uploads the wheel artifacts tested by that release run.
