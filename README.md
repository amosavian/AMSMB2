# AMSMB2


This is small Swift library for iOS, macOS and tvOS which wraps [libsmb2](https://github.com/sahlberg/libsmb2) and allows to connect a SMB2/3 share and do file operation.

[![Swift Version][swift-image]][swift-url]
[![Platform][platform-image]](#)
[![License][license-image]][license-url]
[![Release version][release-image]][release-url]

[![Swift Version Compatibility][swift-version-image]][swift-version-url]
[![Platform Compatibility ][platform-image]][platform-url]

## Getting Started

To use AMSMB2, add the following dependency to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/amosavian/AMSMB2", .upToNextMinor(from: "3.0.0"))
]
```

You can then add the specific product dependency to your target:

```swift
dependencies: [
    .product(name: "AMSMB2", package: "AMSMB2"),
]
```

## Usage

Just read inline help to find what each function does. It's straightforward. It's thread safe.

To do listing files in directory and file operations you must use this template:

```swift
import AMSMB2

class SMBClient: @unchecked Sendable {
    /// connect to: `smb://guest@XXX.XXX.XX.XX/share`
    
    let serverURL = URL(string: "smb://XXX.XXX.XX.XX")!
    let credential = URLCredential(user: "guest", password: "", persistence: URLCredential.Persistence.forSession)
    let share = "share"
    
    lazy private var client = SMB2Manager(url: self.serverURL, credential: self.credential)!
    
    private func connect() async throws -> SMB2Manager {
        // AMSMB2 can handle queueing connection requests
        try await client.connectShare(name: self.share)
        return self.client
    }
    
    func listDirectory(path: String) {
        Task {
            do {
                let client = try await connect()
                let files = try await client.contentsOfDirectory(atPath: path)
                for entry in files {
                    print(
                        "name:", entry[.nameKey] as! String,
                        ", path:", entry[.pathKey] as! String,
                        ", type:", entry[.fileResourceTypeKey] as! URLFileResourceType,
                        ", size:", entry[.fileSizeKey] as! Int64,
                        ", modified:", entry[.contentModificationDateKey] as! Date,
                        ", created:", entry[.creationDateKey] as! Date)
                }
            } catch {
                print(error)
            }
        }
    }
    
    func moveItem(path: String, to toPath: String) {
        Task {
            do {
                let client = try await self.connect()
                try await client.moveItem(atPath: path, toPath: toPath)
                print("\(path) moved successfully.")
                
                // Disconnecting is optional, it will be called eventually
                // when `AMSMB2` object is freed.
                // You may call it explicitly to detect errors.
                try await client.disconnectShare()
            } catch {
                print(error)
            }
        }
    }
}

```

## License

While source code shipped with project is MIT licensed, but it has static link to `libsmb2` which is `LGPL v2.1`, consequently the whole project becomes `LGPL v2.1`.

You **must** link this library dynamically to your app if you intend to distribute your app on App Store.

[swift-image]: https://img.shields.io/badge/swift-5.0-orange.svg
[swift-url]: https://swift.org/
[platform-image]: https://img.shields.io/cocoapods/p/AMSMB2.svg
[license-image]: https://img.shields.io/github/license/amosavian/AMSMB2.svg
[license-url]: LICENSE

[swift-version-image]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FAMSMB2%2Fbadge%3Ftype%3Dswift-versions
[swift-version-url]: https://swiftpackageindex.com/amosavian/AMSMB2
[platform-image]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Famosavian%2FAMSMB2%2Fbadge%3Ftype%3Dplatforms
[platform-url]: https://swiftpackageindex.com/amosavian/AMSMB2
[release-image]: https://img.shields.io/github/release/amosavian/AMSMB2.svg
[release-url]: https://github.com/amosavian/AMSMB2/releases
