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
        .testTarget(
            name: "LocklarkSafariSharedTests",
            dependencies: ["LocklarkSafariShared"],
            path: "Tests/LocklarkSafariSharedTests"
        ),
    ]
)
