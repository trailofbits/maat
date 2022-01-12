include(CMakeFindDependencyMacro)

find_dependency(GMP)

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
