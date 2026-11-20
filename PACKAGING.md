# Building Python wheels

Maat ships as `pymaat` on PyPI and imports as `maat`. The [wheel workflow](.github/workflows/python-package.yml) builds one `cp312-abi3` wheel per platform (Linux x86-64, macOS Intel, and macOS arm64). The binary supports GIL-enabled CPython 3.12 and later through the stable ABI. Linux wheels require glibc 2.28 or later, and macOS wheels require macOS 14 or later. The wheel includes the processor files the extension loads at runtime.

## Build locally

Install GMP, Z3, and LIEF as described in [BUILDING.md](BUILDING.md), then run these commands from the repository root with uv installed.

```sh
git submodule update --init
uv build --wheel --python 3.12
uv venv --python 3.13 /tmp/pymaat-test
uv pip install --python /tmp/pymaat-test/bin/python dist/*.whl
/tmp/pymaat-test/bin/python -I -c 'from maat import ARCH, MaatEngine; MaatEngine(ARCH.X64)'
```

The local build uses the pinned Sleigh submodule. If Sleigh is already installed, pass `-Ccmake.define.maat_USE_EXTERNAL_SLEIGH=ON` to `uv build`. Set `CMAKE_PREFIX_PATH` for dependencies installed outside standard locations. The Python package version comes from Git tags.

## Python API and typing

The wheel ships `maat/_native.pyi` and `py.typed`. Nanobind derives signatures from the C++ functions and converters registered in the extension. The build imports that extension, so optional features such as `Solver` appear in the stub when enabled. The final generation step records positional-only arguments, nonconstructible types and subclass restrictions from the bindings. The Python facade re-exports the same objects for scripts and type checkers.

Native classes now allow class-level monkey-patching, for example `maat.Value.extra_attribute = 1`. Instances still reject arbitrary new attributes. Native factories are callable nanobind objects. Type and function reflection now reports the private implementation module, `maat._native`. Hidden result classes have private names there, and factory functions have nanobind signature metadata. Invalid arguments can raise different exception types. For example, an integer outside the native 64-bit range passed to `Cst(8, value)` now raises `OverflowError`.

### Checking compatibility against the old extension

The reference is the Z3-enabled extension at `7b349fd`. Install its wheel and the candidate wheel in separate environments. From the repository root, run the same script with each interpreter. The script exercises Python operators, buffer conversions, iterators, solver models, and filesystem and EVM objects.

```sh
/path/to/legacy/bin/python -I tests/typing/behavior.py > /tmp/maat-legacy.json
/path/to/candidate/bin/python -I tests/typing/behavior.py > /tmp/maat-candidate.json
diff -u /tmp/maat-legacy.json /tmp/maat-candidate.json
```

The wheel tests replay `tests/typing/legacy_behavior.json` and compare runtime exports, constants, native members, and generated declarations with `tests/typing/baseline.json`. To extend behavior coverage, add the call to `behavior.py` and regenerate its fixture with the legacy interpreter. The corresponding command for the API inventory is `python -I tests/typing/inventory.py`.

Run `python tests/typing/check.py` in an environment containing the installed candidate wheel, ty, mypy, and Pyright. The checks require the valid consumer script to pass and every marked invalid call to produce a diagnostic.

## CI and releases

On every pull request, cibuildwheel builds and repairs the wheel on CPython 3.12. It audits the binary for stable ABI violations and reuses that wheel for the install and runtime tests on CPython 3.13 through 3.15. Manual runs and releases use the same matrix.

Linux jobs load a local image built from public manylinux_2_28 with native dependencies installed. BuildKit reuses the image layers through the GitHub Actions cache. macOS jobs cache the installed dependencies by architecture, deployment target, toolchain, installer, and Sleigh revision. Pushes to `master` seed the caches and test the wheels. Fork pull requests can reuse the base branch caches and build from public sources on a miss. Release jobs build dependencies from scratch. Only a published GitHub release can start the PyPI trusted-publishing job, which uploads the wheel artifacts tested by that release run.
