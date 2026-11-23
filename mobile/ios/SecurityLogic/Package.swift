// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PassmeSecurityLogic",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "PassmeSecurityLogic", targets: ["PassmeSecurityLogic"])],
    targets: [
        .target(name: "PassmeSecurityLogic"),
        .testTarget(name: "PassmeSecurityLogicTests", dependencies: ["PassmeSecurityLogic"])
    ],
    swiftLanguageModes: [.v5]
)
