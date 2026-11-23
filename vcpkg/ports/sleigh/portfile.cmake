vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
  OUT_SOURCE_PATH wrapper
  REPO lifting-bits/sleigh
  REF "v${VERSION}"
  SHA512 332900acda280f8559dab68b31fc69c313eaae8dc68ab7c51d7850112ebb55399950d8b9dac0177403c04260876caa3ab562d162f60ca5b1b3b6e7c0c7173b6b
)

# Use the stable patches shipped with this release of the CMake wrapper.
file(GLOB patches "${wrapper}/src/patches/stable/*.patch")
vcpkg_from_github(
  OUT_SOURCE_PATH ghidra
  REPO NationalSecurityAgency/ghidra
  REF "Ghidra_${VERSION}_build"
  SHA512 e4576bd511628fd2d6a64a6803c6c07922b2c0820436480c7acee97fbd49258f00d9cae9cf2a6bea7d14c5aef561ec4eeac82d6d9dbbd79e515bb344e9ad582a
  PATCHES ${patches}
)

vcpkg_cmake_configure(
  SOURCE_PATH "${wrapper}"
  OPTIONS
    "-DFETCHCONTENT_SOURCE_DIR_GHIDRASOURCE=${ghidra}"
    -Dsleigh_BUILD_SLEIGHSPECS=OFF
    -Dsleigh_BUILD_SUPPORT=OFF
  OPTIONS_RELEASE
    -Dsleigh_BUILD_TOOLS=ON
    -Dsleigh_BUILD_DECOMPILER=OFF
    -Dsleigh_BUILD_GHIDRA=OFF
  OPTIONS_DEBUG
    -Dsleigh_BUILD_TOOLS=OFF
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/sleigh)
vcpkg_copy_tools(TOOL_NAMES sleigh AUTO_CLEAN)
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${wrapper}/LICENSE" "${ghidra}/LICENSE" "${ghidra}/NOTICE")
