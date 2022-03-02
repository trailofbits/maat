import os
import os
import shutil
import sys
from pathlib import Path

import cmake_build_extension
from setuptools import setup

source_dir = str(Path(".").absolute().parent.parent)

setup(
    cmdclass=dict(
        build_ext=cmake_build_extension.BuildExtension
    ),
    ext_modules=[
        cmake_build_extension.CMakeExtension(
            name="Maat",
            install_prefix="maat",
            disable_editable=True,
            write_top_level_init=None,
            source_dir=source_dir,
            cmake_configure_options=[
                # Fixed in `master` branch of cmake_build_extension
                # https://github.com/diegoferigo/cmake-build-extension/commit/8972036d978a83ba77b59e46d4137223d209bffd
                f"-DCMAKE_MAKE_PROGRAM={shutil.which('ninja')}",
                f"-DPython3_EXECUTABLE:PATH={sys.executable}",
                "-DCMAKE_BUILD_TYPE=Release",
                "-Dmaat_USE_EXTERNAL_SLEIGH=OFF",
                "-Dmaat_BUILD_PYTHON_BINDINGS:BOOL=ON",
                "-Dmaat_PYTHON_PACKAGING:BOOL=ON",
            ]
        )
    ],
)
