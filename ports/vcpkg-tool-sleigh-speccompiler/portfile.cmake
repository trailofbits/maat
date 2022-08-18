set(VCPKG_POLICY_CMAKE_HELPER_PORT enabled)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lifting-bits/sleigh
    REF cc4d7d209e5b7947f4c28ffb84db722bc750df8d # cmake-presets branch, unmerged
    SHA512 5e407cbb8b013ebe230485cd3dd4f4cb0d9d816d7e2529fc57bb38ab505e4acf18685febbda84cf760193f50ecc29963f702d8a4fd35a78f41a656a35561e755
    HEAD_REF master
)

vcpkg_find_acquire_program(GIT)

set(VCPKG_BUILD_TYPE release) #we only need release here!
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/tools/spec-compiler"
    OPTIONS
        "-DGIT_EXECUTABLE=${GIT}"
)
vcpkg_cmake_install()
vcpkg_copy_tools(
    TOOL_NAMES sleigh
    DESTINATION "${CURRENT_PACKAGES_DIR}/tools/sleigh"
    AUTO_CLEAN
)

file(
    INSTALL "${SOURCE_PATH}/LICENSE"
    DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
    RENAME copyright
)
configure_file("${CMAKE_CURRENT_LIST_DIR}/vcpkg-port-config.cmake" "${CURRENT_PACKAGES_DIR}/share/${PORT}/vcpkg-port-config.cmake" @ONLY)
