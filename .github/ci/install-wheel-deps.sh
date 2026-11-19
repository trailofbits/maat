#!/usr/bin/env bash
set -euo pipefail

project=$(cd "$1" && pwd)
prefix=${CMAKE_PREFIX_PATH:?}
build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT
cd "$build_root"

# Build once per platform with the same deployment target and C++ ABI as the wheel.
curl -fsSLo gmp.tar.xz https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
test "$(cmake -E sha256sum gmp.tar.xz)" = 'a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898  gmp.tar.xz'
tar xf gmp.tar.xz
(cd gmp-6.3.0 && CFLAGS=-O2 CXXFLAGS=-O2 ./configure --prefix="$prefix" --enable-cxx --disable-assembly && make -j4 && make install)

build_dependency() {
  local src=$1
  local build_dir="$PWD/${src##*/}-build"
  shift
  cmake -S "$src" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_POSITION_INDEPENDENT_CODE=ON "$@"
  cmake --build "$build_dir"
  cmake --install "$build_dir"
}

git clone --quiet --depth 1 --branch 1.0.0 https://github.com/lief-project/LIEF lief
test "$(git -C lief rev-parse HEAD)" = d05b3499b6934137e917c009a4df0a9dc8cb11c5
build_dependency lief -DLIEF_EXAMPLES=OFF -DLIEF_PYTHON_API=OFF -DLIEF_TESTS=OFF

git clone --quiet --depth 1 --branch z3-5.4.1 https://github.com/Z3Prover/z3 z3
test "$(git -C z3 rev-parse HEAD)" = 145c0c51570a357cc558ce898ce77573ba9d4fbf
build_dependency z3 -DBUILD_SHARED_LIBS=OFF -DZ3_BUILD_EXECUTABLE=OFF -DZ3_BUILD_TEST_EXECUTABLES=OFF

build_dependency "$project/src/third-party/sleigh/sleigh-cmake" -Dsleigh_BUILD_SLEIGHSPECS=OFF -Dsleigh_BUILD_SUPPORT=OFF
