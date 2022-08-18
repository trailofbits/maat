vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lifting-bits/sleigh
    REF cc4d7d209e5b7947f4c28ffb84db722bc750df8d # cmake-presets branch, unmerged
    SHA512 5e407cbb8b013ebe230485cd3dd4f4cb0d9d816d7e2529fc57bb38ab505e4acf18685febbda84cf760193f50ecc29963f702d8a4fd35a78f41a656a35561e755
    HEAD_REF master
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
FEATURES
    "sleighspecs"   sleigh_BUILD_SLEIGHSPECS  # compiled sla files
    "support"       sleigh_BUILD_SUPPORT      # support libraries
)

vcpkg_find_acquire_program(GIT)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        "-DGIT_EXECUTABLE=${GIT}"
        "-DSLEIGH_EXECUTABLE=${SLEIGH_SPECCOMPILER}"
        -Dsleigh_BUILD_TOOLS=OFF
    OPTIONS_RELEASE
        "-Dsleigh_INSTALL_CMAKEDIR=${CURRENT_PACKAGES_DIR}/share/${PORT}"
    OPTIONS_DEBUG
        "-Dsleigh_INSTALL_CMAKEDIR=${CURRENT_PACKAGES_DIR}/debug/share/${PORT}"
    MAYBE_UNUSED_VARIABLES
        SLEIGH_EXECUTABLE
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup()
vcpkg_copy_pdbs()

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
