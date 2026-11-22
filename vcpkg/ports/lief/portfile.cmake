vcpkg_from_github(
  OUT_SOURCE_PATH source
  REPO lief-project/LIEF
  REF "${VERSION}"
  SHA512 35d86d23306be0d9713fe6feb4632d83945a3e81557d12c6bdc23164818981dea30483d9ed7fdd5f8ba91803ceec716244f43527221e407f4b8fae021743e6a3
)

vcpkg_cmake_configure(
  SOURCE_PATH "${source}"
  OPTIONS
    # LIEF uses FetchContent to unpack the local archives in third-party/.
    -DFETCHCONTENT_FULLY_DISCONNECTED=OFF
    -DLIEF_EXAMPLES=OFF
    -DLIEF_PYTHON_API=OFF
    -DLIEF_TESTS=OFF
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/LIEF)
vcpkg_fixup_pkgconfig()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
# Bump the port version when updating the shared notices for this LIEF release.
vcpkg_install_copyright(FILE_LIST "${source}/LICENSE" "${CMAKE_CURRENT_LIST_DIR}/../../../licenses/LIEF-dependencies.txt")
