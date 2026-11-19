# Building Python wheels

Maat ships as `pymaat` on PyPI and imports as `maat`. The [wheel workflow](.github/workflows/python-package.yml) builds one `cp310-abi3` wheel per platform (Linux x86-64, macOS Intel, and macOS arm64). The binary supports GIL-enabled CPython 3.10 and later through the stable ABI. The wheel includes the processor files the extension loads at runtime.

## Build locally

Install GMP, Z3, and LIEF as described in [BUILDING.md](BUILDING.md), then run these commands from the repository root with uv installed.

```sh
git submodule update --init
# Sleigh uses git am to patch its private Ghidra checkout during this build.
GIT_COMMITTER_NAME="Maat build" GIT_COMMITTER_EMAIL=build@example.invalid \
  uv build --wheel --python 3.10
uv venv --python 3.13 /tmp/pymaat-test
uv pip install --python /tmp/pymaat-test/bin/python dist/*.whl
/tmp/pymaat-test/bin/python -I -c 'from maat import ARCH, MaatEngine; MaatEngine(ARCH.X64)'
```

The local build uses the pinned Sleigh submodule. If Sleigh is already installed, pass `-Ccmake.define.maat_USE_EXTERNAL_SLEIGH=ON` to `uv build`. Set `CMAKE_PREFIX_PATH` for dependencies installed outside standard locations. The Python package version comes from Git tags.

## CI and releases

On every pull request, cibuildwheel builds and repairs the wheel on CPython 3.10. It audits the binary for stable ABI violations and reuses that wheel for the install and runtime tests on CPython 3.11 through 3.15. Manual runs and releases use the same matrix.

Linux jobs load a local image built from public manylinux2014 with native dependencies installed. BuildKit reuses the image layers through the GitHub Actions cache. macOS jobs cache the installed dependencies by architecture, deployment target, toolchain, installer, and Sleigh revision. Pushes to `master` seed the caches and test the wheels. Fork pull requests can reuse the base branch caches and build from public sources on a miss. Release jobs build dependencies from scratch. Only a published GitHub release can start the PyPI trusted-publishing job, which uploads the wheel artifacts tested by that release run.
