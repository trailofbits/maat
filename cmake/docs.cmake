# ---- Redefine docs_early_return ----

# This function must be a macro, so the return() takes effect in the calling
# scope. This prevents other targets from being available and potentially
# requiring dependencies. This cuts down on the time it takes to generate
# documentation in CI.
macro(docs_early_return)
  return()
endmacro()

# ---- Dependencies ----

include(FetchContent)
FetchContent_Declare(
  mcss URL
  https://github.com/mosra/m.css/archive/d44d4609099080f881a656d885232bc51bbf101c.zip
  URL_MD5 962fb22a6fa82aaa10b3511d4b08bf73
  SOURCE_DIR "${PROJECT_BINARY_DIR}/mcss"
  UPDATE_DISCONNECTED YES
)
FetchContent_MakeAvailable(mcss)

find_package(Python3 3.6 REQUIRED)

# ---- Declare documentation target ----

set(
  DOXYGEN_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/docs"
  CACHE PATH "Path for the generated Doxygen documentation"
)

set(working_dir "${PROJECT_BINARY_DIR}/docs")

foreach(file IN ITEMS Doxyfile conf.py)
  configure_file("docs/${file}.in" "${working_dir}/${file}" @ONLY)
endforeach()

set(mcss_script "${mcss_SOURCE_DIR}/documentation/doxygen.py")
set(config "${working_dir}/conf.py")

add_custom_target(
  docs
  COMMAND "${CMAKE_COMMAND}" -E remove_directory
  "${DOXYGEN_OUTPUT_DIRECTORY}/html"
  "${DOXYGEN_OUTPUT_DIRECTORY}/xml"
  # Do these copies to work around potential bug in Doxygen
  # https://github.com/doxygen/doxygen/issues/6783
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
  ${PROJECT_SOURCE_DIR}/ressources
  "${DOXYGEN_OUTPUT_DIRECTORY}/html/ressources"
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
  ${PROJECT_SOURCE_DIR}/ressources
  "${DOXYGEN_OUTPUT_DIRECTORY}/xml/ressources"
  COMMAND "${Python3_EXECUTABLE}" "${mcss_script}" "${config}"
  COMMENT "Building documentation using Doxygen and m.css"
  WORKING_DIRECTORY "${working_dir}"
  VERBATIM
)
