# Find the Z3 solver and provide the z3::libz3 target.

find_package(Z3 QUIET CONFIG)
if(Z3_FOUND)
  return()
endif()

# Some Z3 releases put the library in bin/.
find_library(Z3_LIBRARY NAMES z3 PATH_SUFFIXES bin)
find_path(Z3_INCLUDE_DIR NAMES z3++.h PATH_SUFFIXES z3)
mark_as_advanced(Z3_LIBRARY Z3_INCLUDE_DIR)

# Read the selected installation's version, including when cross-compiling.
set(Z3_VERSION "")
if(EXISTS "${Z3_INCLUDE_DIR}/z3_version.h")
  file(STRINGS "${Z3_INCLUDE_DIR}/z3_version.h" _z3_version_line
    REGEX "^#define[ \t]+Z3_FULL_VERSION[ \t]+"
    LIMIT_COUNT 1
  )
  if(_z3_version_line MATCHES "\"([0-9]+(\\.[0-9]+)+)\"")
    set(Z3_VERSION "${CMAKE_MATCH_1}")
  endif()
  unset(_z3_version_line)
endif()
set(Z3_VERSION_STRING "${Z3_VERSION}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Z3
  REQUIRED_VARS Z3_LIBRARY Z3_INCLUDE_DIR
  VERSION_VAR Z3_VERSION
  HANDLE_COMPONENTS
)

if(Z3_FOUND AND NOT TARGET z3::libz3)
  add_library(z3::libz3 UNKNOWN IMPORTED)
  set_target_properties(z3::libz3 PROPERTIES
    IMPORTED_LOCATION "${Z3_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Z3_INCLUDE_DIR}"
  )
endif()
