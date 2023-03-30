# NOTE: A large part of this file is the same as sleigh-speccompiler port
vcpkg_minimum_required(VERSION 2022-10-12) # for ${VERSION}

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lifting-bits/sleigh
    REF "v${VERSION}"
    SHA512 e5c4d30e00904807d1495d6f063fcf18c37763928d43c784905ec357c95f83e1fbffddef2536beb0d25cc5f744235b815e61d5c861304fcbc0b6b3e258b561f0
    HEAD_REF master
)

vcpkg_from_github(
    OUT_SOURCE_PATH GHIDRA_SOURCE_PATH
    REPO NationalSecurityAgency/ghidra
    REF "Ghidra_${VERSION}_build"
    SHA512 f5dbc828e43acabe8e30f293726b7afa7f96aa29eb2d0ea1ccd4688012e9fdf2950fab2cfa7b8a2b94feaa8ec5ffba5d39017c8ec152e592818d6e3b67df3fc7
    HEAD_REF master
)

# Apply sleigh project's patches to ghidra
z_vcpkg_apply_patches(
    SOURCE_PATH "${GHIDRA_SOURCE_PATH}"
    PATCHES
        "${SOURCE_PATH}/src/patches/stable/0001-Small-improvements-to-C-decompiler-testing-from-CLI.patch"
        "${SOURCE_PATH}/src/patches/stable/0002-Add-include-guards-to-decompiler-C-headers.patch"
        "${SOURCE_PATH}/src/patches/stable/0003-Fix-UBSAN-errors-in-decompiler.patch"
        "${SOURCE_PATH}/src/patches/stable/0004-Use-stroull-instead-of-stroul-to-parse-address-offse.patch"
        "${SOURCE_PATH}/src/patches/stable/0005-1-4-decompiler-Add-using-namespace-std-to-all-.cc.patch"
        "${SOURCE_PATH}/src/patches/stable/0006-2-4-decompiler-Remusing-automated-std-namespace-fix.patch"
        "${SOURCE_PATH}/src/patches/stable/0007-3-4-decompiler-Manually-fix-std-namespace-in-generat.patch"
        "${SOURCE_PATH}/src/patches/stable/0008-4-4-decompiler-Manually-fix-missed-std-variable-usag.patch"
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
FEATURES
    "specs"     sleigh_BUILD_SLEIGHSPECS  # compiled sla files
    "support"   sleigh_BUILD_SUPPORT      # support libraries
)

vcpkg_list(SET OPTIONS)
if("specs" IN_LIST FEATURES)
    vcpkg_list(APPEND OPTIONS "-DSLEIGH_EXECUTABLE=${SLEIGH_SPECCOMPILER}")
endif()

vcpkg_find_acquire_program(GIT)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        ${OPTIONS}
        "-DGIT_EXECUTABLE=${GIT}"
        "-DFETCHCONTENT_SOURCE_DIR_GHIDRASOURCE=${GHIDRA_SOURCE_PATH}"
        -Dsleigh_BUILD_TOOLS=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/sleigh)
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
