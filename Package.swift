// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "AMSMB2",
    platforms: [
        .iOS(.v9),
        .macOS(.v10_11),
        .tvOS(.v9),
    ],
    products: [
        .library(name: "AMSMB2",
                 targets: ["AMSMB2"])
    ],
    targets: [
        .binaryTarget(
            name: "libsmb2",
            path: "./libsmb2.xcframework"
        ),
        .target(
            name: "AMSMB2",
            dependencies: [
                "libsmb2"
            ],
            path: "AMSMB2"
        ),
        .testTarget(
            name: "AMSMB2Tests",
            dependencies: ["AMSMB2"],
            path: "AMSMB2Tests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
