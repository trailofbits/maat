vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO lief-project/LIEF
    REF 0.12.3
    SHA512 3f48978af2d96e9e469aca1fc4adcfd3475576ba32273d451f881e33b0fc062b0c2b625af10c54c2a0b6a9678e5ce7666499c1c36f578250dab217352f4717e0
    HEAD_REF master
    PATCHES
        0001-Support-vcpkg.patch
        0002-Fix-Uninitialized-CMake-var.patch
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
FEATURES
    "c-api"          LIEF_C_API             # C API
    "logging"        LIEF_LOGGING           # Enable logging
    "logging-debug"  LIEF_LOGGING_DEBUG     # Enable debug logging
    "enable-json"    LIEF_ENABLE_JSON       # Enable JSON-related APIs

    "elf"            LIEF_ELF               # Build LIEF with ELF module
    "pe"             LIEF_PE                # Build LIEF with PE  module
    "macho"          LIEF_MACHO             # Build LIEF with MachO module

    "oat"            LIEF_OAT               # Build LIEF with OAT module
    "dex"            LIEF_DEX               # Build LIEF with DEX module
    "vdex"           LIEF_VDEX              # Build LIEF with VDEX module
    "art"            LIEF_ART               # Build LIEF with ART module

INVERTED_FEATURES
    "enable-frozen" LIEF_DISABLE_FROZEN    # Disable Frozen even if it is supported
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"

    OPTIONS
        ${FEATURE_OPTIONS}

        -DLIEF_PYTHON_API=OFF
        -DLIEF_USE_CCACHE=OFF
        -DLIEF_TESTS=OFF
        -DLIEF_EXAMPLES=OFF

        # Build with external vcpkg dependencies
        -DLIEF_OPT_MBEDTLS_EXTERNAL=ON
        -DLIEF_OPT_UTFCPP_EXTERNAL=ON
        -DLIEF_EXTERNAL_SPDLOG=ON
        -DLIEF_OPT_NLOHMANN_JSON_EXTERNAL=ON
        -DLIEF_OPT_FROZEN_EXTERNAL=ON
        -DLIEF_OPT_EXTERNAL_LEAF=ON
        "-DLIEF_EXTERNAL_LEAF_DIR=${CURRENT_INSTALLED_DIR}/include"
        -DLIEF_OPT_EXTERNAL_SPAN=ON
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(CONFIG_PATH share/LIEF/cmake)

vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")

# Check if all-caps directory is empty (it won't be on case-insensitive filesystems).
# These files could have been moved during vcpkg_cmake_config_fixup
file(GLOB dir_files "${CURRENT_PACKAGES_DIR}/share/LIEF/*")
list(LENGTH dir_files dir_files_len)
if(dir_files_len EQUAL 0)
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/share/LIEF")
endif()

# Handle copyright
file(INSTALL "${SOURCE_PATH}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
