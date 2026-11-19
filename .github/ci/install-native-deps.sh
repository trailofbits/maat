#!/usr/bin/env bash
set -euo pipefail

# Both CI runners use the x86-64 release binaries.
case "$RUNNER_OS" in
Linux)
  lief_platform=Linux
  sleigh_platform=Linux
  lief_sha=4cbf5c1cded3d6eade043f2a1fc7543ec43960f089d5a5266779a4f694aa09ab
  sleigh_sha=8a1a5adf23df7d23ae3ecfda1e8321b2388d7600dcc6743f2f9652917191ac18
  ;;
macOS)
  lief_platform=Darwin
  sleigh_platform=macOS
  lief_sha=753ffe3cdbf0c29e71a5af3e4f9fa549eef5294f31b504003e79f0d8c441818b
  sleigh_sha=d35704eee70460971ac7192301f59a37a867d807b516cbba75ada50e24fb76a4
  ;;
*)
  echo "Unsupported runner OS: $RUNNER_OS" >&2
  exit 1
  ;;
esac

cd "$RUNNER_TEMP"
prefix="$RUNNER_TEMP/native-deps"
mkdir -p "$prefix"
lief="LIEF-0.12.3-$lief_platform-x86_64.tar.gz"
sleigh="$sleigh_platform-sleigh-10.1.2-2.x86_64.tar.gz"
gh release download 0.12.3 --repo lief-project/LIEF --pattern "$lief"
gh release download v10.1.2-2 --repo lifting-bits/sleigh --pattern "$sleigh"
printf '%s  %s\n' "$lief_sha" "$lief" "$sleigh_sha" "$sleigh" | shasum -a 256 --check
for archive in "$lief" "$sleigh"; do
  tar -xzf "$archive" --strip-components=1 -C "$prefix"
done
echo "CMAKE_PREFIX_PATH=$prefix" >>"$GITHUB_ENV"
