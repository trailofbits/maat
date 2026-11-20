# Tries to find an install of the Z3 Solver library
#
# Initially tries to find the CMake config file that upstream Z3 now supports
#
# Once done this will define at least the following
#  Z3_FOUND - BOOL: System has the GMP library installed
#  Z3_INCLUDE_DIR - PATH: The Z3 include directory
#  Z3_LIBRARY - PATH: The library for z3
#  z3::libz3 - TARGET: The target to link against
#
# If Z3 was built using the CMake buildsystem then it provides its own
# ``Z3Config.cmake`` file for use with the :command:`find_package` command's
# config mode. This module looks for this file and, if found,
# returns its results with no further action.
#
# Set ``Z3_NO_Z3_CMAKE`` to ``ON`` to disable this search.
#
# This file is partly modeled off of CMake's included FindCURL.cmake file

include(FindPackageHandleStandardArgs)

# Try first to find Z3 using its stock cmake files unless the user has provided
# a Z3_ROOT hint that would assume skipping the CONFIG option
if(NOT DEFINED Z3_ROOT AND NOT Z3_NO_Z3_CMAKE)
  # do a find package call to specifically look for the CMake version
  # of z3
  find_package(Z3 QUIET NO_MODULE)
  mark_as_advanced(Z3_DIR)

  # if we found the z3 cmake package then we are done, and
  # can print what we found and return.
  if(Z3_FOUND)
    find_package_handle_standard_args(Z3 HANDLE_COMPONENTS CONFIG_MODE)
    return()
  endif()
endif()

# Note: For some reason official Z3 release places the Linux library in 'bin'
# directory
find_library(Z3_LIBRARY NAMES z3 PATH_SUFFIXES bin)
find_path(Z3_INCLUDE_DIR NAMES z3++.h PATH_SUFFIXES z3)

# Figure out version info
if(EXISTS "${Z3_INCLUDE_DIR}/z3_version.h")
  # Z3 4.8.1+ has the version is in a public header.
  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_MAJOR_VERSION[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_MAJOR_VERSION[\t ]+([0-9]+).*$" "\\1"
         Z3_MAJOR "${z3_version_str}")

  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_MINOR_VERSION[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_MINOR_VERSION[\t ]+([0-9]+).*$" "\\1"
         Z3_MINOR "${z3_version_str}")

  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h"
       z3_version_str REGEX "^#define[\t ]+Z3_BUILD_NUMBER[\t ]+.*")
  string(REGEX REPLACE "^.*Z3_BUILD_NUMBER[\t ]+([0-9]+).*$" "\\1"
         Z3_BUILD "${z3_version_str}")

  set(Z3_VERSION_STRING "${Z3_MAJOR}.${Z3_MINOR}.${Z3_BUILD}")
  unset(z3_version_str)
elseif(NOT CMAKE_CROSSCOMPILING)
  find_program(Z3_EXECUTABLE z3 PATH_SUFFIXES bin)
  if(Z3_EXECUTABLE)
    execute_process (COMMAND "${Z3_EXECUTABLE}" -version
      OUTPUT_VARIABLE libz3_version_str
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    string(REGEX REPLACE "^Z3 version ([0-9.]+).*" "\\1"
      Z3_VERSION_STRING "${libz3_version_str}")
    unset(libz3_version_str)
  endif()
endif()
if(NOT Z3_VERSION_STRING)
  message(WARNING "Cannot determine Z3 version")
  set(Z3_VERSION_STRING "0.0.0")
endif()

mark_as_advanced(Z3_LIBRARY Z3_INCLUDE_DIR Z3_VERSION_STRING)

find_package_handle_standard_args(
  Z3
  REQUIRED_VARS Z3_LIBRARY Z3_INCLUDE_DIR
  VERSION_VAR Z3_VERSION_STRING
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
