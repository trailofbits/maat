#!/usr/bin/env bash
set -euo pipefail

case "$RUNNER_OS/$RUNNER_ARCH" in
Linux/X64)
  lief_sha=81b86bcc69d311a01ec1914d26c31ebbb605ac761ec02f10bc5b588de74a8e91
  sleigh_sha=04aeb501858bbacb1cf7afd75d85a94cd1c1abf00354ce43ffaa1e26e2d55ba8
  ;;
macOS/X64)
  lief_sha=f15541e53344b3bb58078472bd9ab737b9f89cd24d51f46866066e554ead7107
  ;;
macOS/ARM64)
  lief_sha=c7bedf2e2acab9bced1c8701b06261fc6f4eba1957f80cbf86323a3f5e172167
  sleigh_sha=6958f37ba8fd5dfd1ce93397f270380f314c8081a132d1e14753c7baef58b8bc
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

lief_version=1.0.0
install_archive lief-project/LIEF "$lief_version" "LIEF-$lief_version-$(uname -s)-$(uname -m).tar.gz" "$lief_sha"

if [[ -n ${sleigh_sha:-} ]]; then
  install_archive lifting-bits/sleigh v12.2 "$RUNNER_OS-sleigh-12.2-1.$(uname -m).tar.gz" "$sleigh_sha"
else
  sleigh_prefix="$RUNNER_TEMP/native-sleigh"
  if [[ ${SLEIGH_CACHE_HIT:-} != true ]]; then
    # Sleigh 12.2 publishes only an arm64 macOS binary.
    cmake -S "$GITHUB_WORKSPACE/src/third-party/sleigh/sleigh-cmake" -B sleigh-build \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$sleigh_prefix" \
      -Dsleigh_BUILD_SLEIGHSPECS=OFF -Dsleigh_BUILD_SUPPORT=OFF
    cmake --build sleigh-build --target install --parallel 4
  fi
  prefix="$prefix:$sleigh_prefix"
fi

if [[ $RUNNER_OS == Linux ]]; then
  z3='z3-5.4.1-x64-glibc-2.39'
  gh release download z3-5.4.1 --repo Z3Prover/z3 --pattern "$z3.zip"
  echo "b548bac48ef2452b4e09ea2945cf4b011d5f43fcf39e4799df268ee7e0769d85  $z3.zip" | sha256sum --check
  unzip -q "$z3.zip"
  prefix="$prefix:$RUNNER_TEMP/$z3"
fi
echo "CMAKE_PREFIX_PATH=$prefix" >>"$GITHUB_ENV"
