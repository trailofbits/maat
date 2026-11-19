#!/usr/bin/env bash
set -euo pipefail

project=$(cd "$1" && pwd)
prefix=${CMAKE_PREFIX_PATH:?}
cd "$(mktemp -d)"

# Build once per platform with the same deployment target and C++ ABI as the wheel.
if [[ $(uname -s) == Darwin ]]; then
  python3 -c "from urllib.request import urlretrieve; urlretrieve('https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz', 'gmp.tar.xz')"
  echo 'a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898  gmp.tar.xz' | shasum -a 256 --check
  tar xf gmp.tar.xz
  (cd gmp-6.3.0 && ./configure --prefix="$prefix" --enable-cxx --disable-assembly && make -j4 && make install)
else
  yum install -y gmp-devel
fi

build_dependency() {
  local src=$1
  local build_dir="$PWD/${src##*/}-build"
  shift
  cmake -S "$src" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_POSITION_INDEPENDENT_CODE=ON "$@"
  cmake --build "$build_dir"
  cmake --install "$build_dir"
}

git clone --quiet --depth 1 --branch 0.13.2 https://github.com/lief-project/LIEF lief
test "$(git -C lief rev-parse HEAD)" = 2d9855fc7f9d4ce6325245f8b75c98eb7663db60
build_dependency lief -DLIEF_EXAMPLES=OFF -DLIEF_PYTHON_API=OFF -DLIEF_TESTS=OFF

git clone --quiet --depth 1 --branch z3-4.13.4 https://github.com/Z3Prover/z3 z3
test "$(git -C z3 rev-parse HEAD)" = 6f24123f0c9d1d8bd84dec275c5c7aea939a19fe
build_dependency z3 -DZ3_BUILD_LIBZ3_SHARED=OFF -DZ3_BUILD_EXECUTABLE=OFF

# The pinned Sleigh submodule applies a bundled Ghidra patch with git am.
GIT_COMMITTER_NAME=CI GIT_COMMITTER_EMAIL=ci@example.invalid \
  build_dependency "$project/src/third-party/sleigh/sleigh-cmake" -Dsleigh_ENABLE_TESTS=OFF -Dsleigh_ENABLE_EXAMPLES=OFF
