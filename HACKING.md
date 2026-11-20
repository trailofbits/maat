# Hacking

Here is some wisdom to help you build and test this project as a developer and
potential contributor.

## Developer mode

Build system targets that are only useful for developers of this project are
hidden if the `maat_DEVELOPER_MODE` option is disabled. Enabling this
option makes tests and other developer targets and options available. Not
enabling this option means that you are a consumer of this project and thus you
have no need for these targets and options.

Developer mode is always set to on in CI workflows.

### Presets

The project's [configure, build, and test presets][1] require CMake 3.20 or
later. With CMake 3.18 or 3.19, follow the [build instructions](BUILDING.md)
and configure with `-Dmaat_DEVELOPER_MODE=ON -Dmaat_BUILD_PYTHON_BINDINGS=OFF`.
The Python bindings require CMake 3.26 or later.

As a developer, you should create a `CMakeUserPresets.json` file at the root of
the project. The following is a real example of a contributor's user preset (inspect carefully to add, remove, or modify the absolute paths):

```json
{
  "version": 2,
  "configurePresets": [
    {
      "name": "dependencies",
      "hidden": true,
      "cacheVariables": {
        "LIEF_DIR": "<prefix>/src/LIEF/install/share/LIEF/cmake",
        "sleigh_DIR": "<prefix>/src/sleigh/install/lib/cmake/sleigh"
      }
    },
    {
      "name": "dev-common",
      "hidden": true,
      "inherits": [
        "dependencies", "dev-mode", "ci-unix"
      ],
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "CMAKE_CXX_FLAGS_DEBUG": "-O0 -g3",
        "CMAKE_C_COMPILER_LAUNCHER": "/usr/local/bin/ccache",
        "CMAKE_CXX_COMPILER_LAUNCHER": "/usr/local/bin/ccache"
      }
    },
    {
      "name": "dev",
      "inherits": "dev-common",
      "binaryDir": "${sourceDir}/build/dev"
    },
    {
      "name": "dev-share",
      "inherits": "dev-common",
      "binaryDir": "${sourceDir}/build/dev-share",
      "cacheVariables": {
        "BUILD_SHARED_LIBS": true
      }
    },
    {
      "name": "dev-sanitize",
      "inherits": ["dev-common", "ci-sanitize"],
      "binaryDir": "${sourceDir}/build/sanitize",
      "cacheVariables": {
        "CMAKE_CXX_COMPILER": "/usr/local/opt/llvm@13/bin/clang++",
        "CMAKE_C_COMPILER": "/usr/local/opt/llvm@13/bin/clang"
      }
    }
  ],
  "buildPresets":[
    {
      "name": "dev",
      "configurePreset": "dev"
    },
    {
      "name": "dev-share",
      "configurePreset": "dev-share"
    },
    {
      "name": "dev-sanitize",
      "configurePreset": "dev-sanitize"
    }
  ],
  "testPresets": [
    {
      "name": "dev",
      "configurePreset": "dev",
      "configuration": "Debug",
      "output": {
        "outputOnFailure": true
      }
    },
    {
      "name": "dev-share",
      "configurePreset": "dev-share",
      "configuration": "Debug",
      "output": {
        "outputOnFailure": true
      }
    },
    {
      "name": "dev-sanitize",
      "configurePreset": "dev-sanitize",
      "configuration": "Sanitize",
      "output": {
        "outputOnFailure": true
      }
    }
  ]
}
```

`CMakeUserPresets.json` is also the perfect place in which you can put all
sorts of things that you would otherwise want to pass to the configure command
in the terminal.

### Configure, build and test

If you followed the above instructions, then you can configure, build and test
the project respectively with the following commands from the project root on
any operating system with any build system:

```sh
cmake --preset=dev
cmake --build --preset=dev
ctest --preset=dev
```

Please note that both the build and test command accepts a `-j` flag to specify
the number of jobs to use, which should ideally be specified to the number of
threads your CPU has. You may also want to add that to your preset using the
`jobs` property, see the [presets documentation][1] for more details.

Install `pytest` in the interpreter selected by CMake to run the Python tests.
To check an installed wheel’s type hints, install `pytest`, `ty`, `mypy`, and `pyright` in that environment and run `python tests/typing/check.py`.

[1]: https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html

### Update the vendored x86 Sleigh specifications

Create a worktree from current `master` and check out the target release in a
clean Ghidra checkout. Run the following commands from the Maat worktree, with
`ghidra_checkout` set to the path of the Ghidra checkout.

**1. Identify the patches to carry forward.** Read the vendor directory’s
history back to the most recent pristine Ghidra import. The entries above that
import include both the patches from the previous update and any processor
fixes added since.

```sh
vendor=src/third-party/sleigh/processors/x86/data
upstream=Ghidra/Processors/x86/data
git log --topo-order --no-merges --oneline -- "$vendor"
```

**2. Commit the pristine import.** Replace the entire vendor directory with
`$ghidra_checkout/$upstream`, including files added or deleted upstream. Commit
that replacement on its own. Use a subject such as
`Import the Ghidra <version> x86 processor data` and record the upstream tag
and revision in the commit message. Before applying any patches, verify that
these commands print the same tree ID.

```sh
git -C "$ghidra_checkout" rev-parse "HEAD:$upstream"
git rev-parse "HEAD:$vendor"
```

**3. Replay the patches that Maat still needs.** Work through the patches
identified in step 1, oldest first. If upstream now implements the behavior,
run the corresponding Maat regression test against the new import and drop the
patch when the test passes. Otherwise, use `git cherry-pick -x <patch>` and
resolve any conflicts against the new specification. Keep each processor change
in its own commit directly above the import. Existing runtime fixes and tests
carry forward from `master`. Put new runtime changes and tests in separate
commits after the processor patches.

**4. Review, test, and merge.** Compare the patched vendor directory with the
clean Ghidra checkout. The diff should contain only the processor changes Maat
still carries.

```sh
git diff --no-index -- "$ghidra_checkout/$upstream" "$vendor"
```

Build in a fresh build directory and run the native and Python test suites. If
you edit an included `.sinc` file during testing, remove `processors/x86.sla`
and `processors/x86-64.sla` from the build directory before rebuilding so
Sleigh recompiles both specifications. Merge the reviewed PR with **Create a
merge commit** to preserve the import and each patch for the next update.
