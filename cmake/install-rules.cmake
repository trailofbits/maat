# Intentional duplicate maat/maat directory in installed include directory
if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_INSTALL_INCLUDEDIR include/maat CACHE PATH "")
endif()

include(GNUInstallDirs)

include(CMakePackageConfigHelpers)

# find_package(<package>) call for consumers to find this project
set(package maat)

# Includes
install(
  DIRECTORY
  src/include/
  "${PROJECT_BINARY_DIR}/export/"
  "${PROJECT_BINARY_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT maat_Development
)
install(
  FILES
  src/third-party/sleigh/native/sleigh_interface.hpp
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT maat_Development
)

set(other_maat_targets)
if(maat_BUILD_PYTHON_BINDINGS)
  list(APPEND other_maat_targets maat_python)
endif()

install(
  TARGETS maat_maat ${other_maat_targets}
  EXPORT maatTargets
  RUNTIME #
  COMPONENT maat_Runtime
  LIBRARY #
  COMPONENT maat_Runtime
  NAMELINK_COMPONENT maat_Development
  ARCHIVE #
  COMPONENT maat_Development
  LIBRARY #
  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
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

# Allow package maintainers to freely override data file directory
set(
  maat_INSTALL_DATADIR "${CMAKE_INSTALL_DATAROOTDIR}/${package}"
  CACHE PATH "Data file location relative to the install prefix"
)

# Install data files
install(
  DIRECTORY "${PROJECT_BINARY_DIR}/${spec_out_prefix}/"
  DESTINATION "${maat_INSTALL_DATADIR}/${spec_out_prefix}"
  COMPONENT maat_Runtime
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
