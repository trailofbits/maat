import os
import sys
from pathlib import Path

import cmake_build_extension
from setuptools import setup

source_dir = str(Path(".").absolute().parent.parent)
print(f"setup.py: source directory: {source_dir}")


if "CIBUILDWHEEL" in os.environ and os.environ["CIBUILDWHEEL"] == "1":
    CIBW_CMAKE_OPTIONS = ["-DCMAKE_INSTALL_LIBDIR=lib"]
else:
    CIBW_CMAKE_OPTIONS = []

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
                f"-DPython3_EXECUTABLE:PATH={sys.executable}",
                "-DCMAKE_BUILD_TYPE=Release",
                "-Dmaat_BUILD_PYTHON_BINDINGS:BOOL=ON",
            ]
            + CIBW_CMAKE_OPTIONS,
            cmake_component="maat_Python"
        )
    ],
)