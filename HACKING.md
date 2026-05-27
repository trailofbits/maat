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

This project makes use of [presets][1] to simplify the process of configuring
the project. As a developer, you are recommended to always have the [latest
CMake version][2] installed to make use of the latest Quality-of-Life
additions.

You have a few options to pass `maat_DEVELOPER_MODE` to the configure
command, but this project prefers to use presets.

As a developer, you should create a `CMakeUserPresets.json` file at the root of
the project. The following is a real example of a contributor's user preset (inspect carefully to add, remove, or modify the absolute paths):

```json
{
  "version": 2,
  "cmakeMinimumRequired": {
    "major": 3,
    "minor": 15,
    "patch": 0
  },
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
        "CMAKE_CXX_COMPILER": "/usr/local/opt/llvm/bin/clang++",
        "CMAKE_C_COMPILER": "/usr/local/opt/llvm/bin/clang"
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
[2]: https://cmake.org/download/
