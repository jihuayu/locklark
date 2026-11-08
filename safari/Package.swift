// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LocklarkSafari",
    platforms: [.macOS(.v13)],
    products: [
        .library(
            name: "LocklarkSafariShared",
            targets: ["LocklarkSafariShared"]
        )
    ],
    targets: [
        .target(
            name: "LocklarkSafariShared",
            path: "Shared/Sources"
        ),
        // Standalone native probe: verifies the SIGPIPE policy under the
        // default disposition in its own process, never in the XCTest host.
        .executableTarget(
            name: "LocklarkSafariSIGPipeProbe",
            dependencies: ["LocklarkSafariShared"],
            path: "TestProbe/Sources"
        ),
        .testTarget(
            name: "LocklarkSafariSharedTests",
            dependencies: ["LocklarkSafariShared"],
            path: "Tests/LocklarkSafariSharedTests"
        ),
    ]
)
