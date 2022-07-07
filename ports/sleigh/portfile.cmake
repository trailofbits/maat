vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lifting-bits/sleigh
    REF 814b41c45dd4ce357bd1982a6c7e01c3dbcc1aa8 # cmake-presets branch, unmerged
    SHA512 ff0273f092f3f546f4beed50d0dba8cdb885a4ef3d623acd62b3fb2cfe50c5a20993ca7d193dd8170847676e86177362f338e5d4ac20a8080b6f0bb253ea9ac8
    HEAD_REF master
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
FEATURES
    "sleighspecs"   sleigh_BUILD_SLEIGHSPECS  # compiled sla files
    "spec-compiler" sleigh_BUILD_SPECCOMPILER # Compiler
    "decompiler"    sleigh_BUILD_DECOMPILER   # Decompiler
    "ghidra"        sleigh_BUILD_GHIDRA       # Ghidra
    "support"       sleigh_BUILD_SUPPORT      # Support libraries
    "extra-tools"   sleigh_BUILD_EXTRATOOLS   # Extra tools
)

set(tools "")
if("spec-compiler" IN_LIST FEATURES)
    list(APPEND tools "sleigh")
endif()
if("decompiler" IN_LIST FEATURES)
    list(APPEND tools "decomp")
endif()
if("ghidra" IN_LIST FEATURES)
    list(APPEND tools "ghidra")
endif()

# The tools won't be built unless this option is enabled
if("tools" IN_LIST FEATURES OR tools)
    list(APPEND FEATURE_OPTIONS "-Dsleigh_BUILD_TOOLS=ON")
endif()

vcpkg_find_acquire_program(GIT)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        "-DGIT_EXECUTABLE=${GIT}"
    OPTIONS_RELEASE
        "-Dsleigh_INSTALL_CMAKEDIR=${CURRENT_PACKAGES_DIR}/share/${PORT}"
    OPTIONS_DEBUG
        "-Dsleigh_INSTALL_CMAKEDIR=${CURRENT_PACKAGES_DIR}/debug/share/${PORT}"
    MAYBE_UNUSED_VARIABLES
        sleigh_BUILD_DECOMPILER
        sleigh_BUILD_GHIDRA
        sleigh_BUILD_SPECCOMPILER
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup()
vcpkg_copy_pdbs()

if(tools)
    vcpkg_copy_tools(
        TOOL_NAMES ${tools}
        AUTO_CLEAN
    )
endif()

if(EXISTS "${CURRENT_PACKAGES_DIR}/share/${PORT}/${PORT}Targets-debug.cmake")
    foreach(tool ${tools})
        vcpkg_replace_string(
            "${CURRENT_PACKAGES_DIR}/share/${PORT}/${PORT}Targets-debug.cmake"
            "tools/${PORT}/${tool}_dbg"
            "tools/${PORT}/${tool}"
        )
    endforeach()
endif()

if("extra-tools" IN_LIST FEATURES)
    vcpkg_copy_tools(
        TOOL_NAMES sleighLift
        AUTO_CLEAN
    )
endif()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")
if(VCPKG_LIBRARY_LINKAGE STREQUAL "static" OR NOT VCPKG_TARGET_IS_WINDOWS)
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/bin")
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/bin")
endif()

file(INSTALL "${SOURCE_PATH}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
