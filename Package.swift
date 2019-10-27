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
    targets: [
        .target(
            name: "SMB2",
            path: "libsmb2",
            publicHeadersPath: "libsmb2/include",
            linkerSettings: [
                .linkedLibrary("smb2-macos", .when(platforms: [.macOS])),
                .linkedLibrary("smb2-ios", .when(platforms: [.iOS])),
                .linkedLibrary("smb2-tvos", .when(platforms: [.tvOS])),
            ]
        ),
        .target(
            name: "AMSMB2",
            dependencies: ["SMB2"],
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
