// swift-tools-version:5.9
import PackageDescription

// Local Swift package for the ClipySi shared Rust core.
//
// `ClipySiCoreFFI.xcframework` and `Sources/ClipySiCore/clipy_si_core_ffi.swift` are build
// outputs of `../../../build-xcframework.sh`. The XCFramework is git-ignored; the generated
// Swift glue is committed so consumers can test bindings from a fresh checkout. While this
// repository is private, the macOS app consumes the core through a pinned git submodule. If the
// repository becomes public, this package can switch to `binaryTarget(url:checksum:)` using the
// release asset checksum.
let package = Package(
    name: "ClipySiCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ClipySiCore", targets: ["ClipySiCore"])
    ],
    targets: [
        .binaryTarget(
            name: "ClipySiCoreFFI",
            path: "ClipySiCoreFFI.xcframework"
        ),
        .target(
            name: "ClipySiCore",
            dependencies: ["ClipySiCoreFFI"],
            path: "Sources/ClipySiCore"
        ),
        .testTarget(
            name: "ClipySiCoreTests",
            dependencies: ["ClipySiCore"],
            path: "Tests/ClipySiCoreTests"
        ),
    ]
)
