include(CMakePackageConfigHelpers)

# find_package(<package>) call for consumers to find this project
set(package maat)

install(
    DIRECTORY
    src/include/
    "${PROJECT_BINARY_DIR}/export/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT maat_Development
)
install(
    FILES
    src/third-party/sleigh/native/sleigh_interface.hpp
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT maat_Development
)

install(
    TARGETS maat_maat
    EXPORT maatTargets
    RUNTIME #
    COMPONENT maat_Runtime
    LIBRARY #
    COMPONENT maat_Runtime
    NAMELINK_COMPONENT maat_Development
    ARCHIVE #
    COMPONENT maat_Development
    INCLUDES #
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

write_basic_package_version_file(
    "${package}ConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)

# Allow package maintainers to freely override the path for the configs
set(
    maat_INSTALL_CMAKEDIR "${CMAKE_INSTALL_DATAROOTDIR}/${package}"
    CACHE PATH "CMake package config location relative to the install prefix"
)
mark_as_advanced(maat_INSTALL_CMAKEDIR)

install(
    FILES cmake/install-config.cmake
    DESTINATION "${maat_INSTALL_CMAKEDIR}"
    RENAME "${package}Config.cmake"
    COMPONENT maat_Development
)

install(
    FILES "${PROJECT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${maat_INSTALL_CMAKEDIR}"
    COMPONENT maat_Development
)

install(
    EXPORT maatTargets
    NAMESPACE maat::
    DESTINATION "${maat_INSTALL_CMAKEDIR}"
    COMPONENT maat_Development
)

# Install data files
install(
  DIRECTORY "${PROJECT_BINARY_DIR}/sleigh/"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/processors"
  COMPONENT maat_Runtime
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
