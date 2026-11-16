// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PassmeSafari",
    platforms: [.macOS(.v13)],
    products: [
        .library(
            name: "PassmeSafariShared",
            targets: ["PassmeSafariShared"]
        )
    ],
    targets: [
        .target(
            name: "PassmeSafariShared",
            path: "Shared/Sources"
        ),
        // Standalone native probe: verifies the SIGPIPE policy under the
        // default disposition in its own process, never in the XCTest host.
        .executableTarget(
            name: "PassmeSafariSIGPipeProbe",
            dependencies: ["PassmeSafariShared"],
            path: "TestProbe/Sources"
        ),
        .testTarget(
            name: "PassmeSafariSharedTests",
            dependencies: ["PassmeSafariShared"],
            path: "Tests/PassmeSafariSharedTests"
        ),
    ]
)
