# Tries to find an install of the Z3 Solver library
#
# Initially tries to find the CMake config file that upstream Z3 now supports
#
# Once done this will define at least the following
#  Z3_FOUND - BOOL: System has the GMP library installed
#  Z3_INCLUDE_DIR - PATH: The Z3 include directory
#  Z3_LIBRARY - PATH: The library for z3
#  z3::libz3 - TARGET: The target to link against

# Try first to find Z3 using its stock cmake files unless the user has provided
# a Z3_ROOT hint that would assume skipping the CONFIG option
if (NOT DEFINED Z3_ROOT)
  find_package(Z3 QUIET CONFIG)
endif()

# If we found with CONFIG mode, then simply finish with everything found
if (Z3_FOUND)
  set(Z3_VERSION "${Z3_VERSION_STRING}")
  find_package_handle_standard_args(Z3 CONFIG_MODE)

# Else do manual finding
else()
  # Note: For some reason official Z3 release places the Linux library in 'bin'
  # directory
  find_library(Z3_LIBRARY NAMES z3 PATH_SUFFIXES bin)
  find_path(Z3_INCLUDE_DIR NAMES z3++.h PATH_SUFFIXES z3)
  find_program(Z3_EXECUTABLE z3 PATH_SUFFIXES bin)

  set(Z3_VERSION_STRING "")

  # Figure out version info
  if(Z3_EXECUTABLE)
    execute_process (COMMAND ${Z3_EXECUTABLE} -version
      OUTPUT_VARIABLE libz3_version_str
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(REGEX REPLACE "^Z3 version ([0-9.]+).*" "\\1"
      Z3_VERSION_STRING "${libz3_version_str}")
    unset(libz3_version_str)
    set(Z3_VERSION "${Z3_VERSION_STRING}")
  endif()
  mark_as_advanced(Z3_LIBRARY Z3_INCLUDE_DIR Z3_VERSION_STRING)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(
    Z3
    REQUIRED_VARS Z3_LIBRARY Z3_INCLUDE_DIR
    VERSION_VAR Z3_VERSION
  )

  # Match target name to what is in upstream
  if(NOT TARGET z3::libz3)
    add_library(z3::libz3 UNKNOWN IMPORTED)
    set_property(
      TARGET z3::libz3 PROPERTY
      IMPORTED_LOCATION "${Z3_LIBRARY}"
    )
    set_property(
      TARGET z3::libz3 PROPERTY
      INTERFACE_INCLUDE_DIRECTORIES "${Z3_INCLUDE_DIR}"
    )
  endif()
endif()
