cmake_minimum_required(VERSION 3.14)

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

add_library(
    maat_maat
    src/ir/asm_inst.cpp
    src/ir/cpu.cpp
    src/ir/instruction.cpp
    src/engine/info.cpp
    src/engine/callother.cpp
    src/engine/snapshot.cpp
    src/engine/symbol.cpp
    src/engine/settings.cpp
    src/engine/logger.cpp
    src/engine/path.cpp
    src/engine/engine.cpp
    src/engine/event.cpp
    src/memory/memory.cpp
    src/memory/symbolic_memory.cpp
    src/memory/memory_map.cpp
    src/third-party/sleigh/native/sleigh_interface.cpp
    src/third-party/murmur3/murmur3.c
    src/solver/solver_z3.cpp
    src/solver/solver.cpp
    src/env/emulated_libs/libc.cpp
    src/env/filesystem.cpp
    src/env/env.cpp
    src/env/emulated_syscalls/linux_syscalls.cpp
    src/env/abi.cpp
    src/env/library.cpp
    src/loader/loader_lief.cpp
    src/loader/loader_lief_elf.cpp
    src/loader/loader.cpp
    src/expression/simplification.cpp
    src/expression/constraint.cpp
    src/expression/number.cpp
    src/expression/varcontext.cpp
    src/expression/value.cpp
    src/expression/expression.cpp
    src/expression/value_set.cpp
    src/arch/arch.cpp
    src/arch/lifter.cpp
    src/arch/lifterX86.cpp
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
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
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

find_package(Z3)
if(Z3_FOUND)
    target_link_libraries(maat_maat PUBLIC z3::libz3)
    target_compile_definitions(maat_maat PUBLIC Z3_BACKEND=1 HAS_SOLVER_BACKEND=1)
endif()

find_package(LIEF)
if(LIEF_FOUND)
    target_link_libraries(maat_maat PUBLIC LIEF::LIEF)
    target_compile_definitions(maat_maat PUBLIC LIEF_BACKEND=1)
endif()

find_package(Python3)
if(Python3_FOUND AND MAAT_BUILD_PYTHON_BINDINGS)
    add_subdirectory(bindings)
endif()

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

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
