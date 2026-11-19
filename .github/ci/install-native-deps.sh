#!/usr/bin/env bash
set -euo pipefail

case "$RUNNER_OS/$RUNNER_ARCH" in
Linux/X64)
  lief_sha=37674fcecfc93e4f28476400d6264bbbe393d779257ce965aaf0c13a5cf71124
  sleigh_sha=8a1a5adf23df7d23ae3ecfda1e8321b2388d7600dcc6743f2f9652917191ac18
  ;;
macOS/X64)
  lief_sha=d5be58c3f44541a45f3f3b2f8a60a38ed484f3f7c2195829ce999dae28349d49
  sleigh_sha=d35704eee70460971ac7192301f59a37a867d807b516cbba75ada50e24fb76a4
  ;;
macOS/ARM64)
  lief_sha=029e274f6d46f6b5729318ad6e90828700f077f649424ab820a348b18d70935f
  ;;
*)
  echo "Unsupported runner: $RUNNER_OS/$RUNNER_ARCH" >&2
  exit 1
  ;;
esac

cd "$RUNNER_TEMP"
prefix="$RUNNER_TEMP/native-deps"
mkdir -p "$prefix"

install_archive() {
  local repo=$1 tag=$2 archive=$3 digest=$4
  gh release download "$tag" --repo "$repo" --pattern "$archive"
  printf '%s  %s\n' "$digest" "$archive" | shasum -a 256 --check
  tar -xzf "$archive" --strip-components=1 -C "$prefix"
}

lief_version=0.13.2
install_archive lief-project/LIEF "$lief_version" "LIEF-$lief_version-$(uname -s)-$(uname -m).tar.gz" "$lief_sha"

if [[ $RUNNER_ARCH == X64 ]]; then
  install_archive lifting-bits/sleigh v10.1.2-2 "$RUNNER_OS-sleigh-10.1.2-2.x86_64.tar.gz" "$sleigh_sha"
else
  # The Sleigh release pinned by the submodule has no arm64 binary.
  # Its configure step uses git am to apply a bundled Ghidra patch.
  GIT_COMMITTER_NAME=CI GIT_COMMITTER_EMAIL=ci@example.invalid \
    cmake -S "$GITHUB_WORKSPACE/src/third-party/sleigh/sleigh-cmake" -B sleigh-build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    -Dsleigh_ENABLE_TESTS=OFF -Dsleigh_ENABLE_EXAMPLES=OFF
  cmake --build sleigh-build --target install
fi
echo "CMAKE_PREFIX_PATH=$prefix" >>"$GITHUB_ENV"
