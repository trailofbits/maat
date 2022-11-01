cmake_minimum_required(VERSION 3.15)

include(cmake/prelude.cmake)

file(READ "Version.txt" maat_version)

project(
  maat
  VERSION ${maat_version}
  DESCRIPTION "Open-source symbolic execution framework: https://maat.re"
  HOMEPAGE_URL "https://github.com/trailofbits/maat"
  LANGUAGES C CXX
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-g")
endif()


include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

# ---- Declare library ----

add_library(maat_maat
  src/arch/arch_EVM.cpp
  src/arch/arch_X86.cpp
  src/arch/arch_RISCV.cpp
  src/arch/arch_ARM32.cpp
  src/arch/lifter.cpp
  src/arch/register_aliases.cpp
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
  src/env/env_EVM.cpp
  src/env/env_linux.cpp
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
  src/ir/ir_cache.cpp
  src/loader/loader.cpp
  src/loader/loader_EVM.cpp
  src/loader/loader_lief.cpp
  src/loader/loader_lief_elf.cpp
  src/memory/memory.cpp
  src/memory/memory_map.cpp
  src/memory/symbolic_memory.cpp
  src/serialization/deserializer.cpp
  src/serialization/serialization_helpers.cpp
  src/serialization/serializer.cpp
  src/solver/solver.cpp
  src/solver/solver_z3.cpp
  src/third-party/murmur3/murmur3.c
  src/third-party/keccak/sha3.cpp
  src/third-party/sleigh/native/reg_translator.cpp
  src/third-party/sleigh/native/sleigh_interface.cpp
)
add_library(maat::maat ALIAS maat_maat)

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
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/keccak>"
  "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/third-party/murmur3>"
)

target_compile_features(maat_maat PUBLIC cxx_std_17)

if(maat_PYTHON_PACKAGING)
  set_target_properties(
    maat_maat PROPERTIES
    EXCLUDE_FROM_ALL 1
    EXCLUDE_FROM_DEFAULT_BUILD 1
  )

  # If packaging python bindings we need to force maat_INSTALL_DATADIR so
  # that Maat's config gets the proper path prefix for the spec files
  # directory
  include(GNUInstallDirs)
  set(maat_INSTALL_DATADIR "${CMAKE_INSTALL_DATADIR}")
endif()

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
  target_compile_definitions(maat_maat PUBLIC MAAT_Z3_BACKEND=1 MAAT_HAS_SOLVER_BACKEND=1)
endif()

if(maat_USE_LIEF)
  find_package(LIEF 0.12 REQUIRED)
  target_link_libraries(maat_maat PUBLIC LIEF::LIEF)
  target_compile_definitions(maat_maat PUBLIC MAAT_LIEF_BACKEND=1 MAAT_HAS_LOADER_BACKEND=1)
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

# Allow user to override sleigh compiler to support cross-compilation. Default
# location is the one imported when we found the sleigh package
if(CMAKE_CROSSCOMPILING)
  find_program(maat_SLEIGH_COMPILER "sleigh_opt"
    DOC "Sleigh compiler executable"
  )
  if(NOT maat_SLEIGH_COMPILER)
    message(FATAL_ERROR "Maat needs a sleigh compiler. Specify path manually by setting 'maat_SLEIGH_COMPILER'")
  endif()
else()
  set(maat_SLEIGH_COMPILER "$<TARGET_FILE:sleigh::sleigh_opt>" CACHE PATH "Sleigh compiler executable")
endif()

macro(maat_sleigh_compile ARCH_DIR ARCH)
  # ARCH_DIR is the directory that appears in Ghidra's source code hierarchy
  # ARCH appears in the name of the '.slaspec' and '.pspec' file (they should be the same)
  # Creates a target maat_sleigh_spec_${ARCH}
  sleigh_compile(
    TARGET maat_sleigh_spec_${ARCH}
    COMPILER "${maat_SLEIGH_COMPILER}"
    SLASPEC "${spec_dir}/${ARCH_DIR}/data/languages/${ARCH}.slaspec"
    LOG_FILE "${PROJECT_BINARY_DIR}/sleigh-log/${ARCH}.log"
    OUT_FILE "${spec_out_dir}/${ARCH}.sla"
  )
  configure_file("${spec_dir}/${ARCH_DIR}/data/languages/${ARCH}.pspec" "${spec_out_dir}/${ARCH}.pspec")
endmacro()

macro(maat_sleigh_compile_files ARCH_DIR ARCH SLASPEC PSPEC)
  # ARCH_DIR is the directory that appears in Ghidra's source code hierarchy
  # ARCH appears in the name of the '.slaspec' and '.pspec' file (they should be the same)
  # Creates a target maat_sleigh_spec_${ARCH}
  sleigh_compile(
    TARGET maat_sleigh_spec_${ARCH}
    COMPILER "${maat_SLEIGH_COMPILER}"
    SLASPEC "${spec_dir}/${ARCH_DIR}/data/languages/${SLASPEC}.slaspec"
    LOG_FILE "${PROJECT_BINARY_DIR}/sleigh-log/${ARCH}.log"
    OUT_FILE "${spec_out_dir}/${SLASPEC}.sla"
  )
  configure_file("${spec_dir}/${ARCH_DIR}/data/languages/${PSPEC}.pspec" "${spec_out_dir}/${PSPEC}.pspec")
endmacro()

maat_sleigh_compile(x86 x86-64)
maat_sleigh_compile(x86 x86)
maat_sleigh_compile(EVM EVM)
maat_sleigh_compile_files(RISCV RISCV riscv.lp64d RV64G)
maat_sleigh_compile_files(ARM ARM32 ARM8_le ARMCortex)

# All of the sla spec targets are combined into this one
add_custom_target(maat_all_sla_specs DEPENDS
  maat_sleigh_spec_x86-64
  maat_sleigh_spec_x86
  maat_sleigh_spec_EVM
  maat_sleigh_spec_RISCV
  maat_sleigh_spec_ARM32
)

# Add sla specs as dependencies to our targets
add_dependencies(maat_maat maat_all_sla_specs)

# ---- Python bindings ----

if(maat_BUILD_PYTHON_BINDINGS)
  # NOTE: The way we use the main library's source files means this needs to
  # be a CMake include rather than add_subdirectory
  include(bindings/bindings.cmake)
  add_dependencies(maat_python maat_all_sla_specs)
endif()

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES AND NOT maat_PYTHON_PACKAGING)
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
