# ---- Developer mode ----

# Developer mode enables targets and code paths in the CMake scripts that are
# only relevant for the developer(s) of maat
# Targets necessary to build the project must be provided unconditionally, so
# consumers can trivially build and package the project
if(PROJECT_IS_TOP_LEVEL)
  option(maat_BUILD_PYTHON_BINDINGS "Build Python bindings" ON)
  option(maat_DEVELOPER_MODE "Enable developer mode" OFF)
  option(BUILD_SHARED_LIBS "Build shared libs." OFF)

  # Allow package maintainers to freely override data file directory
  set(
    CMAKE_INSTALL_DATADIR "share/maat"
    CACHE PATH "Data file location relative to the install prefix"
  )
endif()

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
