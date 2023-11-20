// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "AMSMB2",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .macCatalyst(.v13),
        .tvOS(.v14),
        .watchOS(.v6),
    ],
    products: [
        .library(
            name: "AMSMB2",
            type: .dynamic,
            targets: ["AMSMB2"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "libsmb2",
            path: "Dependencies/libsmb2",
            exclude: [
                "lib/CMakeLists.txt",
                "lib/libsmb2.syms",
                "lib/Makefile.am",
                "lib/Makefile.DC_KOS",
                "lib/Makefile.PS2_EE",
                "lib/Makefile.PS2_IOP",
                "lib/Makefile.PS3_PPU",
                "lib/Makefile.PS4",
            ],
            sources: [
                "lib",
            ],
            publicHeadersPath: ".",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("include/apple"),
                .headerSearchPath("include/smb2"),
                .headerSearchPath("lib"),
                .define("_U_", to: "__attribute__((unused))"),
                .define("HAVE_CONFIG_H", to: "1"),
                .unsafeFlags([
                    "-Wno-everything",
                ]),
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
            dependencies: ["AMSMB2"],
            path: "AMSMB2Tests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
