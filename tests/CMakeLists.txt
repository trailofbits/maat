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
  unit-tests/test_all.cpp
  unit-tests/test_archEVM.cpp
  unit-tests/test_archX64.cpp
  unit-tests/test_archX86.cpp
  unit-tests/test_archARM32.cpp
  unit-tests/test_event.cpp
  unit-tests/test_expression.cpp
  unit-tests/test_ir.cpp
  unit-tests/test_loader.cpp
  unit-tests/test_memory.cpp
  unit-tests/test_serialization.cpp
  unit-tests/test_simplification.cpp
  unit-tests/test_snapshot.cpp
  unit-tests/test_solver.cpp
  unit-tests/test_symbolic_memory.cpp
)
target_link_libraries(unit-tests maat::maat)
target_compile_features(unit-tests PRIVATE cxx_std_17)
target_compile_definitions(unit-tests PRIVATE
  # TODO(ekilmer): The 'spec_out_dir' variable comes from the maat CMakeLists.
  # These tests should be buildable and runnable using an already installed
  # maat from the Config file
  "MAAT_SLEIGH_DIR=\"${spec_out_dir}\""
)

add_test(NAME unit-tests
  COMMAND unit-tests
  # Need this for looking up test binaries
  WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
)

# Advanced tests
add_executable(adv-tests
  adv-tests/test_all.cpp
  adv-tests/test_coverage.cpp
  adv-tests/test_evm.cpp
  adv-tests/test_serialization.cpp
  adv-tests/test_hash.cpp
  adv-tests/test_hash_solving.cpp
  adv-tests/test_solve_symptr.cpp
)
target_link_libraries(adv-tests maat::maat)
target_compile_features(adv-tests PRIVATE cxx_std_17)
target_compile_definitions(adv-tests PRIVATE
  # TODO(ekilmer): The 'spec_out_dir' variable comes from the maat CMakeLists.
  # These tests should be buildable and runnable using an already installed
  # maat from the Config file
  "MAAT_SLEIGH_DIR=\"${spec_out_dir}\""
)

add_test(NAME adv-tests
  COMMAND adv-tests
  # Need this for looking up test binaries
  WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.."
)

if(maat_BUILD_PYTHON_BINDINGS AND maat_RUN_PYTHON_TESTS)
  include(../cmake/pytest.cmake)

  add_test(NAME python-tests
    COMMAND ${pytest_command} .
    # Need to run within the python-tests directory
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/python-tests"
  )

  # Set environment variables for correct operation
  set_tests_properties(python-tests PROPERTIES
    ENVIRONMENT "PYTHONPATH=$<TARGET_FILE_DIR:maat_python>;MAAT_SLEIGH_DIR=${spec_out_dir}"
  )
endif()

#IDE UX
add_folders(Test)
