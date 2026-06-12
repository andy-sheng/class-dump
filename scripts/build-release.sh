#!/bin/bash
#
# Build a release (universal arm64 + x86_64) class-dump binary and package it
# into a .zip under build/release/.
#
# Usage:
#   scripts/build-release.sh
#
# Environment overrides:
#   CONFIGURATION   Build configuration (default: Release)
#   ARCHS           Architectures to build (default: "arm64 x86_64")
#   OUTPUT_DIR      Where the packaged artifacts go (default: build/release)

set -euo pipefail

# Move to the repository root regardless of where the script is invoked from.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIGURATION="${CONFIGURATION:-Release}"
ARCHS="${ARCHS:-arm64 x86_64}"
OUTPUT_DIR="${OUTPUT_DIR:-build/release}"
DERIVED_DATA="build/DerivedData"

echo "==> Building class-dump ($CONFIGURATION, archs: $ARCHS)"
xcodebuild \
    -project class-dump.xcodeproj \
    -scheme class-dump \
    -configuration "$CONFIGURATION" \
    -derivedDataPath "$DERIVED_DATA" \
    ARCHS="$ARCHS" \
    ONLY_ACTIVE_ARCH=NO \
    MACOSX_DEPLOYMENT_TARGET=10.13 \
    build

BINARY="$DERIVED_DATA/Build/Products/$CONFIGURATION/class-dump"
if [[ ! -f "$BINARY" ]]; then
    echo "error: built binary not found at $BINARY" >&2
    exit 1
fi

echo "==> Built:"
lipo -info "$BINARY"
"$BINARY" --version

VERSION="$("$BINARY" --version 2>/dev/null | head -1 | awk '{print $2}')"
VERSION="${VERSION:-unknown}"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cp "$BINARY" "$OUTPUT_DIR/class-dump"

ARCHIVE="$OUTPUT_DIR/class-dump-${VERSION}.zip"
# Use ditto so the zip is clean and preserves the executable bit.
ditto -c -k --sequesterRsrc "$OUTPUT_DIR/class-dump" "$ARCHIVE"

echo "==> Packaged: $ARCHIVE"
shasum -a 256 "$ARCHIVE"
