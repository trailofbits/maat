cmake_minimum_required(VERSION 3.15)
project("maat_find_package_test")

find_package(maat REQUIRED)

add_executable(maat_find_package_test
  src/main.cpp
)

target_link_libraries(maat_find_package_test PRIVATE
  maat::maat
)
