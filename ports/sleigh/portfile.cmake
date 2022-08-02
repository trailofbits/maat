vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lifting-bits/sleigh
    REF 04db45f0b73372aa038e79b7e3fc44c3eb14732b # cmake-presets branch, unmerged
    SHA512 f1ed643e25a021f42bcb201a184bb453d8a546df4c1e0157fad3d36ff883ddb1dc5076610f074e8ae184eb389d60dbd0f03e9000d1cc60b629578d95e7a99d0c
    HEAD_REF master
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
FEATURES
    "sleighspecs"   sleigh_BUILD_SLEIGHSPECS  # compiled sla files
    "spec-compiler" sleigh_BUILD_SPECCOMPILER # sla spec compiler
    "decompiler"    sleigh_BUILD_DECOMPILER   # decompiler
    "ghidra"        sleigh_BUILD_GHIDRA       # ghidra tool
    "support"       sleigh_BUILD_SUPPORT      # support libraries
    "extra-tools"   sleigh_BUILD_EXTRATOOLS   # extra tools
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

file(
    INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
