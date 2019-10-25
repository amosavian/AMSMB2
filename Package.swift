// swift-tools-version:5.0
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
        dependencies: [
            .package(path: "../libsmb2")
        ],
        targets: [
            .target(
                name: "AMSMB2",
                dependencies: ["SMB2"],
                path: "AMSMB2",
                linkerSettings: [
                    .unsafeFlags(["-Xlinker -lsmb2"]),
                ]
            ),
        ],
        swiftLanguageVersions: [.v5]
    )
