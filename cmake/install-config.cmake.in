include(CMakeFindDependencyMacro)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
find_dependency(GMP)

# NOTE(ekilmer): This is a private dependency that only needs to be found if we
# are statically linking
if(NOT "@BUILD_SHARED_LIBS@")
  find_dependency(sleigh)
endif()

if("@Z3_FOUND@")
  find_dependency(Z3)
endif()

if("@LIEF_FOUND@")
  find_dependency(LIEF)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/maatTargets.cmake")
