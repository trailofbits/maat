# ---- Python bindings ----
find_package(Python3 COMPONENTS Development REQUIRED)

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
  bindings/python/py_event.cpp
  bindings/python/py_filesystem.cpp
  bindings/python/py_info.cpp
  bindings/python/py_loader.cpp
  bindings/python/py_maat.cpp
  bindings/python/py_memory.cpp
  bindings/python/py_path.cpp
  bindings/python/py_process.cpp
  bindings/python/py_settings.cpp
  bindings/python/py_solver.cpp
  bindings/python/py_value.cpp
  bindings/python/util.cpp

  ${maat_sources}
)
add_library(maat::python ALIAS maat_python)

set_target_properties(
  maat_python PROPERTIES
  # TODO: Visibility settings should ideally be hidden
  #CXX_VISIBILITY_PRESET hidden
  #VISIBILITY_INLINES_HIDDEN YES
  # See issue https://gitlab.kitware.com/cmake/cmake/-/issues/20782
  #VERSION "${PROJECT_VERSION}"
  #SOVERSION "${PROJECT_VERSION_MAJOR}"
  EXPORT_NAME python
  OUTPUT_NAME maat
  PREFIX ""
)

target_include_directories(
  maat_python ${warning_guard}
  PRIVATE
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/sleigh/native>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/murmur3>"
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
)

target_include_directories(
  maat_python SYSTEM
  PRIVATE
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/export>"
)

target_compile_features(maat_python PRIVATE cxx_std_17)
target_compile_definitions(maat_python PRIVATE PYTHON_BINDINGS=1)

target_link_libraries(maat_python PRIVATE
  Python3::Module
  GMP::GMP
  sleigh::sla
)

if(maat_USE_Z3)
  target_link_libraries(maat_python PRIVATE z3::libz3)
  # TODO: Should these definitions be prefixed by MAAT_?
  target_compile_definitions(maat_python PRIVATE Z3_BACKEND=1 HAS_SOLVER_BACKEND=1)
endif()

if(maat_USE_LIEF)
  target_link_libraries(maat_python PRIVATE LIEF::LIEF)
  # TODO: Should these definitions be prefixed by MAAT_?
  target_compile_definitions(maat_python PRIVATE LIEF_BACKEND=1 HAS_LOADER_BACKEND=1)
endif()
