# ---- Developer mode ----

# Developer mode enables targets and code paths in the CMake scripts that are
# only relevant for the developer(s) of maat
# Targets necessary to build the project must be provided unconditionally, so
# consumers can trivially build and package the project
if(PROJECT_IS_TOP_LEVEL)
  option(maat_BUILD_PYTHON_BINDINGS "Build Python bindings" ON)
  # The following option is used when packaging the Python bindings
  option(maat_PYTHON_PACKAGING "Indicative that this build configuration is used during Python packaging" OFF)

  option(maat_DEVELOPER_MODE "Enable developer mode" OFF)
  option(maat_RUN_PYTHON_TESTS "Enable running the Python tests" ON)
  option(BUILD_SHARED_LIBS "Build shared libs." OFF)
  
  # Enable folder support
  set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

# These variables correspond to the dependencies that maat doesn't
# technically require but are almost always desirable to find. We include
# these options to let an advanced user implement their own backends
option(maat_USE_Z3 "Build with Z3 solver backend" ON)
option(maat_USE_LIEF "Build with LIEF loader backend" ON)

# Optionally use vendored dependencies
option(maat_USE_EXTERNAL_SLEIGH "Find an external installation of sleigh" ON)

# ---- Suppress C4251 on Windows ----

# Please see include/maat/maat.hpp for more details
set(pragma_suppress_c4251 "
/* This needs to suppress only for MSVC */
#if defined(_MSC_VER) && !defined(__ICL)
#  define MAAT_SUPPRESS_C4251 _Pragma(\"warning(suppress:4251)\")
#else
#  define MAAT_SUPPRESS_C4251
#endif
")

# ---- Warning guard ----

# target_include_directories with the SYSTEM modifier will request the compiler
# to omit warnings from the provided paths, if the compiler supports that
# This is to provide a user experience similar to find_package when
# add_subdirectory or FetchContent is used to consume this project
set(warning_guard "")
if(NOT PROJECT_IS_TOP_LEVEL)
  option(
    maat_INCLUDES_WITH_SYSTEM
    "Use SYSTEM modifier for maat's includes, disabling warnings"
    ON
  )
  mark_as_advanced(maat_INCLUDES_WITH_SYSTEM)
  if(maat_INCLUDES_WITH_SYSTEM)
    set(warning_guard SYSTEM)
  endif()
endif()
