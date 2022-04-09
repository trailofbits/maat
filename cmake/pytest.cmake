find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(pytest_command "${Python3_EXECUTABLE}" -m pytest)

# Check that pytest module exists
execute_process(
  COMMAND ${pytest_command} --version
  OUTPUT_VARIABLE pytest_out
  RESULT_VARIABLE pytest_exists
)

if(NOT pytest_exists EQUAL 0)
  message(FATAL_ERROR "Could not find Python pytest package")
endif()

message(STATUS "Found ${pytest_out}")
