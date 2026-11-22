# Building Python wheels

Maat ships as `pymaat` on PyPI and imports as `maat`. The [wheel workflow](.github/workflows/python-package.yml) builds one `cp312-abi3` wheel per platform (Linux x86-64, macOS Intel, and macOS arm64). The binary supports GIL-enabled CPython 3.12 and later through the stable ABI. Linux wheels require glibc 2.28 or later, and macOS wheels require macOS 14 or later. The wheel includes the processor files the extension loads at runtime.

## Build locally

Install the native dependencies listed in [BUILDING.md](BUILDING.md), including the Sleigh library and compiler. Set `CMAKE_PREFIX_PATH` for dependencies installed outside standard locations. From the repository root, build the wheel and test it in a fresh environment.

```sh
uv build --wheel --python 3.12
uv venv --python 3.13 ../pymaat-test
uv pip install --python ../pymaat-test/bin/python dist/*.whl
../pymaat-test/bin/python -I -c 'import maat; maat.MaatEngine(maat.ARCH.X64)'
```

To build with the bundled Sleigh, run `git submodule update --init` and pass `-Ccmake.define.maat_USE_EXTERNAL_SLEIGH=OFF` to `uv build`. The Python package version comes from Git tags.

## CI and releases

CI audits each wheel for stable ABI violations and tests the same wheel on multiple CPython versions.

Linux jobs load a local image built from public manylinux_2_28 with native dependencies installed. BuildKit reuses the image layers through the GitHub Actions cache. macOS jobs cache the installed dependencies by architecture, deployment target, toolchain, installer, and Sleigh revision. Pushes to `master` seed the caches and test the wheels. Fork pull requests can reuse the base branch caches and build from public sources on a miss. Release jobs build dependencies from scratch. Only a published GitHub release can start the PyPI trusted-publishing job, which uploads the wheel artifacts tested by that release run.
