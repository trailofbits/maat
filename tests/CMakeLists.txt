cmake_minimum_required(VERSION 3.14)

project(maatTests LANGUAGES CXX)
include(../cmake/project-is-top-level.cmake)
include(../cmake/folders.cmake)

if(PROJECT_IS_TOP_LEVEL)
    find_package(maat REQUIRED)
    enable_testing()
endif()

# Unit tests
add_executable(unit-tests
    unit-tests/test_ir.cpp
    unit-tests/test_snapshot.cpp
    unit-tests/test_memory.cpp
    unit-tests/test_symbolic_memory.cpp
    unit-tests/test_event.cpp
    unit-tests/test_archX86.cpp
    unit-tests/test_simplification.cpp
    unit-tests/test_archX64.cpp
    unit-tests/test_expression.cpp
    unit-tests/test_all.cpp
    unit-tests/test_solver.cpp
    unit-tests/test_loader.cpp
)
target_link_libraries(unit-tests maat::maat)
target_compile_features(unit-tests PRIVATE cxx_std_17)

add_test(NAME unit-tests COMMAND unit-tests)

# Advanced tests
add_executable(adv-tests
    adv-tests/test_hash_solving.cpp
    adv-tests/test_hash.cpp
    adv-tests/test_solve_symptr.cpp
    adv-tests/test_coverage.cpp
    adv-tests/test_all.cpp
)
target_link_libraries(adv-tests maat::maat)
target_compile_features(adv-tests PRIVATE cxx_std_17)

add_test(NAME adv-tests COMMAND adv-tests)

#IDE UX
add_folders(Test)
