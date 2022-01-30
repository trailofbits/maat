#
# Copyright (c) 2022-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.21.0)
project("maat_find_package_test")

find_package(maat REQUIRED)

add_executable(maat_find_package_test
  src/main.cpp
)

target_link_libraries(maat_find_package_test PRIVATE
  maat::maat
)

# TODO(alex): This seems wrong that we need to know about transitive dependencies.
#             Figure this out later.
find_package(Z3)
if (Z3_FOUND)
  target_link_libraries(maat_find_package_test PRIVATE z3::libz3)
endif()

find_package(LIEF)
if (LIEF_FOUND)
  target_link_libraries(maat_find_package_test PRIVATE LIEF::LIEF)
endif()
