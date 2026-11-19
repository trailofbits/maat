# ---- Python bindings ----
if(${CMAKE_VERSION} VERSION_LESS "3.18.0")
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
else()
  find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)
endif()

execute_process(
  COMMAND "${Python3_EXECUTABLE}" -c "if True:
    import sysconfig
    print(sysconfig.get_config_var('EXT_SUFFIX'))"
  OUTPUT_VARIABLE python_soabi
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the same source files as the main library uses
# NOTE: These source file paths are relative to where the maat::maat target was
# declared, so this file needs to be "include"d instead of add_subdirectory by
# CMake
get_target_property(maat_sources maat::maat SOURCES)

add_library(maat_python MODULE
  bindings/python/py_arch.cpp
  bindings/python/py_config.cpp
  bindings/python/py_constraint.cpp
  bindings/python/py_cpu.cpp
  bindings/python/py_engine.cpp
  bindings/python/py_env.cpp
  bindings/python/py_env_EVM.cpp
  bindings/python/py_event.cpp
  bindings/python/py_filesystem.cpp
  bindings/python/py_info.cpp
  bindings/python/py_loader.cpp
  bindings/python/py_maat.cpp
  bindings/python/py_memory.cpp
  bindings/python/py_path.cpp
  bindings/python/py_process.cpp
  bindings/python/py_serialization.cpp
  bindings/python/py_settings.cpp
  bindings/python/py_solver.cpp
  bindings/python/py_stats.cpp
  bindings/python/py_value.cpp
  bindings/python/util.cpp

  ${maat_sources}
)
add_library(maat::python ALIAS maat_python)

set_target_properties(
  maat_python PROPERTIES
  # See issue https://gitlab.kitware.com/cmake/cmake/-/issues/20782
  #VERSION "${PROJECT_VERSION}"
  #SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
  EXPORT_NAME python
  OUTPUT_NAME maat
  SUFFIX "${python_soabi}"
  PREFIX ""
)

target_include_directories(
  maat_python ${warning_guard}
  PRIVATE
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/keccak>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/murmur3>"
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/bindings/python>"
)

target_compile_features(maat_python PRIVATE cxx_std_17)
target_compile_definitions(maat_python PRIVATE MAAT_PYTHON_BINDINGS=1)

target_link_libraries(maat_python PRIVATE
  Python3::Module
  GMP::GMP
  sleigh::sla
)

if(maat_USE_Z3)
  target_link_libraries(maat_python PRIVATE z3::libz3)
  target_compile_definitions(maat_python PRIVATE MAAT_Z3_BACKEND=1 MAAT_HAS_SOLVER_BACKEND=1)
endif()

if(maat_USE_LIEF)
  target_link_libraries(maat_python PRIVATE LIEF::LIEF)
  target_compile_definitions(maat_python PRIVATE MAAT_LIEF_BACKEND=1 MAAT_HAS_LOADER_BACKEND=1)
endif()

include(GNUInstallDirs)
set(python_spec_dir "maat/${CMAKE_INSTALL_DATADIR}/${spec_out_prefix}")

if(NOT CMAKE_SKIP_INSTALL_RULES)
  if(NOT DEFINED maat_INSTALL_PYTHONMODULEDIR)
    if(maat_PYTHON_PACKAGING)
      # The wheel builder sets its install prefix to site-packages/maat.
      set(python_site_rel "..")
    else()
      execute_process(
        COMMAND "${Python3_EXECUTABLE}" -c
          "import sysconfig; print(sysconfig.get_path('platlib', vars={'base': '.', 'platbase': '.'}))"
        OUTPUT_VARIABLE python_site_rel
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE python_site_status
      )
      if(NOT python_site_status EQUAL 0)
        message(FATAL_ERROR "Could not determine the Python module install directory")
      endif()
    endif()
    set(maat_INSTALL_PYTHONMODULEDIR "${python_site_rel}" CACHE STRING
      "Python module directory relative to the install prefix")
  endif()

  install(
    TARGETS maat_python
    LIBRARY #
    COMPONENT maat_Python
    LIBRARY #
    DESTINATION "${maat_INSTALL_PYTHONMODULEDIR}"
  )

  install(
    DIRECTORY "${PROJECT_BINARY_DIR}/${spec_out_prefix}/"
    DESTINATION "${maat_INSTALL_PYTHONMODULEDIR}/${python_spec_dir}"
    COMPONENT maat_Python
  )
endif()
