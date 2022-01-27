cmake_minimum_required(VERSION 3.15)

include(cmake/prelude.cmake)

project(
  maat
  VERSION 0.1.0
  DESCRIPTION "Open-source symbolic execution framework: https://maat.re"
  HOMEPAGE_URL "https://github.com/trailofbits/maat"
  LANGUAGES C CXX
)

docs_early_return()

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

# ---- Declare library ----

add_library(maat_maat
  src/arch/arch.cpp
  src/arch/lifter.cpp
  src/arch/lifterX86.cpp
  src/engine/callother.cpp
  src/engine/engine.cpp
  src/engine/event.cpp
  src/engine/info.cpp
  src/engine/logger.cpp
  src/engine/path.cpp
  src/engine/settings.cpp
  src/engine/snapshot.cpp
  src/engine/symbol.cpp
  src/env/abi.cpp
  src/env/emulated_libs/libc.cpp
  src/env/emulated_syscalls/linux_syscalls.cpp
  src/env/env.cpp
  src/env/filesystem.cpp
  src/env/library.cpp
  src/expression/constraint.cpp
  src/expression/expression.cpp
  src/expression/number.cpp
  src/expression/simplification.cpp
  src/expression/value.cpp
  src/expression/value_set.cpp
  src/expression/varcontext.cpp
  src/ir/asm_inst.cpp
  src/ir/cpu.cpp
  src/ir/instruction.cpp
  src/loader/loader.cpp
  src/loader/loader_lief.cpp
  src/loader/loader_lief_elf.cpp
  src/memory/memory.cpp
  src/memory/memory_map.cpp
  src/memory/symbolic_memory.cpp
  src/solver/solver.cpp
  src/solver/solver_z3.cpp
  src/third-party/murmur3/murmur3.c
  src/third-party/sleigh/native/sleigh_interface.cpp
)
add_library(maat::maat ALIAS maat_maat)

include(GenerateExportHeader)
generate_export_header(
  maat_maat
  BASE_NAME maat
  EXPORT_FILE_NAME export/maat/maat_export.hpp
  CUSTOM_CONTENT_FROM_VARIABLE pragma_suppress_c4251
)

if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(maat_maat PUBLIC MAAT_STATIC_DEFINE)
endif()

set_target_properties(
  maat_maat PROPERTIES
  # TODO: Visibility settings should ideally be hidden
  #CXX_VISIBILITY_PRESET hidden
  #VISIBILITY_INLINES_HIDDEN YES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  EXPORT_NAME maat
  OUTPUT_NAME maat
)

target_include_directories(
  maat_maat ${warning_guard}
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/sleigh/native>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/murmur3>"
)

target_include_directories(
  maat_maat SYSTEM
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/export>"
)

target_compile_features(maat_maat PUBLIC cxx_std_17)

# ---- Find our dependencies ----

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake/modules)

find_package(GMP REQUIRED)
find_package(sleigh REQUIRED)
target_link_libraries(
  maat_maat
  PUBLIC GMP::GMP
  PRIVATE sleigh::sla
)

# TODO: Should this be REQUIRED or gated by an option?
find_package(Z3)
if(Z3_FOUND)
  target_link_libraries(maat_maat PUBLIC z3::libz3)
  # TODO: Should these definitions be prefixed by MAAT_?
  target_compile_definitions(maat_maat PUBLIC Z3_BACKEND=1 HAS_SOLVER_BACKEND=1)
endif()

# TODO: Should this be REQUIRED or gated by an option?
find_package(LIEF)
if(LIEF_FOUND)
  target_link_libraries(maat_maat PUBLIC LIEF::LIEF)
  # TODO: Should these definitions be prefixed by MAAT_?
  target_compile_definitions(maat_maat PUBLIC LIEF_BACKEND=1 HAS_LOADER_BACKEND=1)
endif()

if(maat_BUILD_PYTHON_BINDINGS)
  # NOTE: The way we use the main library's source files means this needs to
  # be a CMake include rather than add_subdirectory
  include(bindings/bindings.cmake)
endif()

# ---- Compile Sleigh data ----

# Path created like ${maat_INSTALL_DATADIR}/${spec_out_prefix}
set(spec_out_prefix "processors")
set(spec_out_dir "${PROJECT_BINARY_DIR}/${spec_out_prefix}")
set(spec_log_dir "${PROJECT_BINARY_DIR}/sleigh-log")
set(spec_dir "${PROJECT_SOURCE_DIR}/src/third-party/sleigh/processors")

add_custom_command(
  OUTPUT "${spec_out_dir}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${spec_out_dir}"
)
add_custom_command(
  OUTPUT "${spec_log_dir}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${spec_log_dir}"
)

# x86-64
sleigh_compile(
  TARGET maat_sleigh_spec_x86-64
  SLASPEC "${spec_dir}/x86/data/languages/x86-64.slaspec"
  LOG_FILE "${PROJECT_BINARY_DIR}/sleigh-log/x86-64.log"
  OUT_FILE "${spec_out_dir}/x86-64.sla"
)
configure_file("${spec_dir}/x86/data/languages/x86-64.pspec" "${spec_out_dir}/x86-64.pspec")

# x86
sleigh_compile(
  TARGET maat_sleigh_spec_x86
  SLASPEC "${spec_dir}/x86/data/languages/x86.slaspec"
  LOG_FILE "${PROJECT_BINARY_DIR}/sleigh-log/x86.log"
  OUT_FILE "${spec_out_dir}/x86.sla"
)
configure_file("${spec_dir}/x86/data/languages/x86.pspec" "${spec_out_dir}/x86.pspec")

# All of the sla spec targets are combined into this one
add_custom_target(maat_all_sla_specs ALL DEPENDS
  maat_sleigh_spec_x86-64
  maat_sleigh_spec_x86
)

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

# Embed hard-coded installation information to help detect "normal" installation
# paths for locating data files.
# NOTE(ekilmer): Needs to be after the install rules so that we can get the
# standard CMake installation locations... not sure how well this works if the
# project is embedded in a project that turns off the installation rules
configure_file(generate/src/include/maat/config.hpp.in "${PROJECT_BINARY_DIR}/include/maat/config.hpp" @ONLY)
target_include_directories(maat_maat PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>")

# ---- Developer mode ----

if(NOT maat_DEVELOPER_MODE)
  return()
elseif(NOT PROJECT_IS_TOP_LEVEL)
  message(
    AUTHOR_WARNING
    "Developer mode is intended for developers of maat"
  )
endif()

include(cmake/dev-mode.cmake)
