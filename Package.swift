// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "LibraryName",
    // platforms: [.iOS("9.0"), .macOS("10.11"), tvOS("9.0")],
    products: [
        .library(name: "AMSMB2", targets: ["AMSMB2"])
    ],
    targets: [
        .target(
            name: "AMSMB2",
            path: "AMSMB2"
        )
    ]
)
