// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AMSMB2",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .macCatalyst(.v13),
        .tvOS(.v14),
        .watchOS(.v6),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "AMSMB2",
            type: .dynamic,
            targets: ["AMSMB2"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-atomics.git", .upToNextMajor(from: "1.2.0")),
    ],
    targets: [
        .target(
            name: "libsmb2",
            path: "Dependencies/libsmb2",
            exclude: [
                "lib/CMakeLists.txt",
                "lib/libsmb2.syms",
                "lib/Makefile.am",
                "lib/Makefile.AMIGA",
                "lib/Makefile.AMIGA_AROS",
                "lib/Makefile.AMIGA_OS3",
                "lib/Makefile.PS3_PPU",
                "lib/ps2",
            ],
            sources: [
                "lib",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("include/apple"),
                .headerSearchPath("include/smb2"),
                .headerSearchPath("lib"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
            ],
            linkerSettings: [
            ]
        ),
        .target(
            name: "AMSMB2",
            dependencies: [
                "libsmb2",
            ],
            path: "AMSMB2"
        ),
        .testTarget(
            name: "AMSMB2Tests",
            dependencies: [
                "AMSMB2",
                .product(name: "Atomics", package: "swift-atomics"),
            ],
            path: "AMSMB2Tests"
        ),
    ]
)

for target in package.targets {
    let swiftSettings: [SwiftSetting] = [
        .enableUpcomingFeature("ExistentialAny"),
    ]
    target.swiftSettings = swiftSettings
}
