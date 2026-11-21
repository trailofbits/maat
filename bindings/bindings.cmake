# ---- Python bindings ----
# FindPython3 gained stable ABI module support in CMake 3.26.
cmake_minimum_required(VERSION 3.26)
if(DEFINED Python3_EXECUTABLE)
  set(Python_EXECUTABLE "${Python3_EXECUTABLE}")
endif()
find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.Module Development.SABIModule)
set(Python3_EXECUTABLE "${Python_EXECUTABLE}")
execute_process(COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_VARIABLE nanobind_DIR OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
find_package(nanobind 3.1 CONFIG REQUIRED)
# FindPython3 started reporting the free-threaded build flag in CMake 4.4.
if(NOT DEFINED Python_FREE_THREADED AND NOT CMAKE_CROSSCOMPILING)
  execute_process(
    COMMAND "${Python3_EXECUTABLE}" -c
      "import sysconfig; print(sysconfig.get_config_var('Py_GIL_DISABLED') or 0)"
    OUTPUT_VARIABLE Python_FREE_THREADED
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
  )
endif()
if(Python_FREE_THREADED)
  message(FATAL_ERROR "Building the cp312-abi3 extension requires GIL-enabled CPython")
endif()

# Get the same source files as the main library uses
# NOTE: These source file paths are relative to where the maat::maat target was
# declared, so this file needs to be "include"d instead of add_subdirectory by
# CMake
get_target_property(maat_sources maat::maat SOURCES)

nanobind_add_module(maat_python STABLE_ABI NOMINSIZE PROTECT_STACK
  bindings/python/py_constants.cpp
  bindings/python/py_constraint.cpp
  bindings/python/py_cpu.cpp
  bindings/python/py_engine.cpp
  bindings/python/py_env_EVM.cpp
  bindings/python/py_event.cpp
  bindings/python/py_environment.cpp
  bindings/python/py_info.cpp
  bindings/python/py_maat.cpp
  bindings/python/py_memory.cpp
  bindings/python/py_path.cpp
  bindings/python/py_settings.cpp
  bindings/python/py_solver.cpp
  bindings/python/py_stats.cpp
  bindings/python/py_value.cpp
  bindings/python/py_varcontext.cpp
  bindings/python/util.cpp

  ${maat_sources}
)
add_library(maat::python ALIAS maat_python)
# On CPython 3.15 the discovered stable suffix can be abi3t even on a
# GIL-enabled interpreter. The linked nanobind target uses the 3.12 limited API.
if(UNIX AND NOT CYGWIN)
  set_property(TARGET maat_python PROPERTY SUFFIX ".abi3${CMAKE_SHARED_MODULE_SUFFIX}")
endif()

set_target_properties(
  maat_python PROPERTIES
  # See issue https://gitlab.kitware.com/cmake/cmake/-/issues/20782
  #VERSION "${PROJECT_VERSION}"
  #SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
  EXPORT_NAME python
  OUTPUT_NAME _native
  LIBRARY_OUTPUT_DIRECTORY "$<1:${PROJECT_BINARY_DIR}/maat>"
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
set(python_spec_dir "${CMAKE_INSTALL_DATADIR}/${spec_out_prefix}")
configure_file(bindings/python/maat/__init__.py maat/__init__.py COPYONLY)
configure_file(bindings/python/maat/py.typed maat/py.typed COPYONLY)
nanobind_add_stub(maat_python_raw_stub MODULE maat._native
  OUTPUT "${PROJECT_BINARY_DIR}/_native.raw.pyi" PYTHON_PATH "${PROJECT_BINARY_DIR}"
  INCLUDE_PRIVATE DEPENDS maat_python)
add_custom_command(
  OUTPUT "${PROJECT_BINARY_DIR}/maat/_native.pyi"
  COMMAND "${Python_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/bindings/python/finish_stub.py"
          "${PROJECT_BINARY_DIR}/_native.raw.pyi" "${PROJECT_BINARY_DIR}/maat/_native.pyi"
  DEPENDS "${PROJECT_BINARY_DIR}/_native.raw.pyi" "${PROJECT_SOURCE_DIR}/bindings/python/finish_stub.py"
  VERBATIM)
add_custom_target(maat_python_stub ALL DEPENDS "${PROJECT_BINARY_DIR}/maat/_native.pyi")
add_dependencies(maat_python_stub maat_python_raw_stub)

if(NOT CMAKE_SKIP_INSTALL_RULES)
  if(NOT DEFINED maat_INSTALL_PYTHONMODULEDIR)
    if(maat_PYTHON_PACKAGING)
      # The packaging backend installs directly into the wheel root.
      set(python_site_rel ".")
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
    DESTINATION "${maat_INSTALL_PYTHONMODULEDIR}/maat"
  )

  install(FILES bindings/python/maat/__init__.py bindings/python/maat/py.typed
    "${PROJECT_BINARY_DIR}/maat/_native.pyi"
    DESTINATION "${maat_INSTALL_PYTHONMODULEDIR}/maat" COMPONENT maat_Python)
  install(
    DIRECTORY "${PROJECT_BINARY_DIR}/${spec_out_prefix}/"
    DESTINATION "${maat_INSTALL_PYTHONMODULEDIR}/maat/${python_spec_dir}"
    COMPONENT maat_Python
  )
endif()
