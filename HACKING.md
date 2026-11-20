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

Note that if you are building the python bindings you need to install `pytest` in order to
run the tests.

[1]: https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html

### Update the vendored x86 Sleigh specifications

Start in a worktree branched from current `master`. Before copying any files,
list the processor patches from the previous update and subsequent changes to
the vendor directory. For Ghidra 12.2, the pristine import was `47a352a` and
its twelve processor patches ended at `9364e04`.

```sh
vendor=src/third-party/sleigh/processors/x86/data
previous_import=47a352a  # Use the most recent pristine import.
git log --reverse --no-merges --oneline "$previous_import"..HEAD -- "$vendor"
git diff "$previous_import" HEAD -- "$vendor"
```

Replace the entire vendor directory with `Ghidra/Processors/x86/data` from the
target release, including upstream deletions. Commit the import alone and
record the upstream tag and commit in its message. Verify that these two tree
IDs match before applying patches.

```sh
git -C "$ghidra_checkout" rev-parse "${ghidra_tag}:Ghidra/Processors/x86/data"
git rev-parse "HEAD:$vendor"
new_import=$(git rev-parse HEAD)
```

Review the listed patches in order. For each adaptation that Maat still needs,
run `git cherry-pick -x <patch>` and resolve any conflicts against the new
specification. When upstream implements the behavior, skip
the patch and run its existing Maat test against the new import. Keep each
remaining processor change in its own commit directly above the import.
Runtime fixes and regression tests already on `master` carry forward with the
branch. Put any new runtime fixes and tests in separate commits after the
processor patches.

Review the resulting downstream changes with
`git diff "$new_import" HEAD -- "$vendor"`. Build in a fresh build directory and
run the native and Python suites. When testing incremental edits to included `.sinc` files, remove the
generated `processors/x86.sla` and `processors/x86-64.sla` from the build
directory first so Sleigh recompiles both. Merge the reviewed PR with a merge
commit to preserve the import and the individual patches for the next update.
