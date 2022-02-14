cmake_minimum_required(VERSION 3.15)

include(cmake/prelude.cmake)

project(
  maat
  VERSION 0.1.0
  DESCRIPTION "Open-source symbolic execution framework: https://maat.re"
  HOMEPAGE_URL "https://github.com/trailofbits/maat"
  LANGUAGES C CXX
)

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

# ---- Declare library ----

add_library(maat_maat
  src/arch/arch.cpp
  src/arch/lifter.cpp
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
  # TODO: Uncomment after workaround to use lifting-bits sleigh
  # src/third-party/sleigh/native/sleigh_interface.cpp
)
add_library(maat::maat ALIAS maat_maat)

# TODO: Workaround to use lifting-bits sleigh
configure_file(src/third-party/sleigh/native/sleigh_interface.cpp "${PROJECT_BINARY_DIR}/src/sleigh_interface.cpp" COPYONLY)
target_sources(maat_maat PRIVATE "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/src/sleigh_interface.cpp>")

if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(maat_maat PUBLIC MAAT_STATIC_DEFINE)
endif()

set_target_properties(
  maat_maat PROPERTIES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
  EXPORT_NAME maat
  OUTPUT_NAME maat
)

target_include_directories(
  maat_maat ${warning_guard}
  PUBLIC
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/murmur3>"
)

target_compile_features(maat_maat PUBLIC cxx_std_17)

# ---- Find our dependencies ----

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake/modules)

find_package(GMP REQUIRED)

if(maat_USE_EXTERNAL_SLEIGH)
  find_package(sleigh REQUIRED)
else()
  set(sleigh_ENABLE_TESTS OFF CACHE BOOL "")
  add_subdirectory(src/third-party/sleigh/sleigh-cmake sleigh EXCLUDE_FROM_ALL)
endif()

target_link_libraries(
  maat_maat
  PUBLIC GMP::GMP
  PRIVATE sleigh::sla
)

if(maat_USE_Z3)
  find_package(Z3 REQUIRED)
  target_link_libraries(maat_maat PUBLIC z3::libz3)
  # TODO: Prefix with MAAT_
  target_compile_definitions(maat_maat PUBLIC MAAT_Z3_BACKEND=1 MAAT_HAS_SOLVER_BACKEND=1)
endif()

if(maat_USE_LIEF)
  find_package(LIEF REQUIRED)
  target_link_libraries(maat_maat PUBLIC LIEF::LIEF)
  # TODO: Prefix with MAAT_
  target_compile_definitions(maat_maat PUBLIC MAAT_LIEF_BACKEND=1 MAAT_HAS_LOADER_BACKEND=1)
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

macro(maat_sleigh_compile ARCH_DIR ARCH)
  # ARCH_DIR is the directory that appears in Ghidra's source code hierarchy
  # ARCH appears in the name of the '.slaspec' and '.pspec' file (they should be the same)
  # Creates a target maat_sleigh_spec_${ARCH}
  sleigh_compile(
    TARGET maat_sleigh_spec_${ARCH}
    SLASPEC "${spec_dir}/${ARCH_DIR}/data/languages/${ARCH}.slaspec"
    LOG_FILE "${PROJECT_BINARY_DIR}/sleigh-log/${ARCH}.log"
    OUT_FILE "${spec_out_dir}/${ARCH}.sla"
  )
  configure_file("${spec_dir}/${ARCH_DIR}/data/languages/${ARCH}.pspec" "${spec_out_dir}/${ARCH}.pspec")
endmacro()

maat_sleigh_compile(x86 x86-64)
maat_sleigh_compile(x86 x86)

# All of the sla spec targets are combined into this one
add_custom_target(maat_all_sla_specs DEPENDS
  maat_sleigh_spec_x86-64
  maat_sleigh_spec_x86
)

# Add sla specs as dependencies to our targets
add_dependencies(maat_maat maat_all_sla_specs)
if(maat_BUILD_PYTHON_BINDINGS)
  add_dependencies(maat_python maat_all_sla_specs)
endif()

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

# Embed hard-coded installation information to help detect "normal" installation
# paths for locating data files.
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
