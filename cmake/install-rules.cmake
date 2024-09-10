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
  "${PROJECT_BINARY_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT maat_Development
)

# Optional targets
set(other_maat_targets)

# Needed only if using vendored library and not building as shared library
# because sleigh is always a static library
if(NOT maat_USE_EXTERNAL_SLEIGH AND NOT BUILD_SHARED_LIBS)
  list(APPEND other_maat_targets sleigh_sla)
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
  COMPATIBILITY SameMinorVersion
)

# Allow package maintainers to freely override the path for the configs
set(
  maat_INSTALL_CMAKEDIR "${CMAKE_INSTALL_DATAROOTDIR}/${package}"
  CACHE PATH "CMake package config location relative to the install prefix"
)
mark_as_advanced(maat_INSTALL_CMAKEDIR)

configure_file(
  cmake/install-config.cmake.in
  "${PROJECT_BINARY_DIR}/install-config.cmake"
  @ONLY
)
install(
  FILES "${PROJECT_BINARY_DIR}/install-config.cmake"
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
  maat_INSTALL_DATADIR "${CMAKE_INSTALL_DATADIR}/${package}"
  CACHE PATH "Data file location relative to the install prefix"
)

# Install data files
install(
  DIRECTORY "${PROJECT_BINARY_DIR}/${spec_out_prefix}/"
  DESTINATION "${maat_INSTALL_DATADIR}/${spec_out_prefix}"
  COMPONENT maat_Runtime
)

# Install CMake helper for finding GMP
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/cmake/modules/"
  DESTINATION "${maat_INSTALL_CMAKEDIR}/modules"
  COMPONENT maat_Development
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
