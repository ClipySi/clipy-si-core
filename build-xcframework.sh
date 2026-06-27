#!/usr/bin/env bash
# Build the universal (arm64 + x86_64) ClipySiCore XCFramework and refresh the local
# Swift package consumed by Clipy.xcodeproj during development (M8.2).
#
#   ./build-xcframework.sh            # release build (default)
#   PROFILE=dev ./build-xcframework.sh   # faster debug build for iteration
#
# Outputs (both git-ignored — regenerate with this script):
#   bindings/swift/ClipySiCore/ClipySiCoreFFI.xcframework      (binary)
#   bindings/swift/ClipySiCore/Sources/ClipySiCore/clipy_si_core_ffi.swift  (generated)
#
# The cargo toolchain is not on PATH in this environment; callers must export it, e.g.
#   export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
set -euo pipefail

cd "$(dirname "$0")"
CRATE_DIR="$(pwd)"
PKG_DIR="$CRATE_DIR/bindings/swift/ClipySiCore"
PROFILE="${PROFILE:-release}"
LIB="libclipy_si_core_ffi.a"

if [ "$PROFILE" = "release" ]; then
  CARGO_PROFILE_FLAG="--release"; PROFILE_PATH="release"
else
  CARGO_PROFILE_FLAG=""; PROFILE_PATH="debug"
fi

echo "==> Building static libs ($PROFILE) for arm64 + x86_64"
cargo build $CARGO_PROFILE_FLAG -p clipy-si-core-ffi --target aarch64-apple-darwin
cargo build $CARGO_PROFILE_FLAG -p clipy-si-core-ffi --target x86_64-apple-darwin

ARM64_LIB="target/aarch64-apple-darwin/$PROFILE_PATH/$LIB"
X86_64_LIB="target/x86_64-apple-darwin/$PROFILE_PATH/$LIB"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> lipo -> universal macOS static lib"
mkdir -p "$WORK/macos"
lipo -create "$ARM64_LIB" "$X86_64_LIB" -output "$WORK/macos/$LIB"

echo "==> Generating Swift bindings (library mode)"
# Use the just-built dylib for metadata extraction (host arch debug dylib is enough).
cargo build -p clipy-si-core-ffi >/dev/null
cargo run --quiet --bin uniffi-bindgen -- generate \
  --library "target/debug/libclipy_si_core_ffi.dylib" \
  --language swift --out-dir "$WORK/gen"

# Headers dir for the xcframework: the C header + a Clang module map named `module.modulemap`.
mkdir -p "$WORK/headers"
cp "$WORK/gen/clipy_si_core_ffiFFI.h" "$WORK/headers/"
cp "$WORK/gen/clipy_si_core_ffiFFI.modulemap" "$WORK/headers/module.modulemap"

echo "==> Assembling ClipySiCoreFFI.xcframework"
rm -rf "$PKG_DIR/ClipySiCoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$WORK/macos/$LIB" -headers "$WORK/headers" \
  -output "$PKG_DIR/ClipySiCoreFFI.xcframework"

# Copy the generated Swift glue LAST: with `set -e`, if the xcframework assembly above fails the
# script aborts before touching the committed .swift, so we never leave updated glue (new
# checksums) paired with a stale/missing binary.
echo "==> Refreshing generated Swift in the local package"
mkdir -p "$PKG_DIR/Sources/ClipySiCore"
cp "$WORK/gen/clipy_si_core_ffi.swift" "$PKG_DIR/Sources/ClipySiCore/clipy_si_core_ffi.swift"

echo "==> Done."
echo "    XCFramework: $PKG_DIR/ClipySiCoreFFI.xcframework"
echo "    Swift glue : $PKG_DIR/Sources/ClipySiCore/clipy_si_core_ffi.swift"
