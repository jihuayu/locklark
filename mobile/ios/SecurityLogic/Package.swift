// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "LocklarkSecurityLogic",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "LocklarkSecurityLogic", targets: ["LocklarkSecurityLogic"])],
    targets: [
        .target(name: "LocklarkSecurityLogic"),
        .testTarget(name: "LocklarkSecurityLogicTests", dependencies: ["LocklarkSecurityLogic"])
    ],
    swiftLanguageModes: [.v5]
)
