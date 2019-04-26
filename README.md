# AMSMB2


This is small Swift library for iOS, macOS and tvOS which wraps [libsmb2](https://github.com/sahlberg/libsmb2) and allows to connect a SMB2/3 share and do file operation.

[![Swift Version][swift-image]][swift-url]
[![Platform][platform-image]](#)
[![License][license-image]][license-url]

[![Build Status][travis-image]][travis-url]
[![Release version][release-image]][release-url]
[![CocoaPods version][pod-release-image]][cocoapods]
[![Carthage compatible][carthage-image]](https://github.com/Carthage/Carthage)
[![Accio supported](accio-image)](https://github.com/JamitLabs/Accio)

## Install

### Cocoapods / Carthage

Add this line to your pods file:

```ruby
pod "AMSMB2"
```

Or add this to Cartfile:

```
github "amosavian/AMSMB2"
```

### Accio

Add the following to your Package.swift:

```swift
.package(url: "https://github.com/amosavian/AMSMB2.git", .upToNextMajor(from: "2.0.0")),
```

Next, add `AMSMB2` to your App targets dependencies like so:

```swift
.target(
    name: "App",
    dependencies: [
        "AMSMB2",
    ]
),
```

Then run `accio update`.

### Manually

To have latest updates with ease, use this command on terminal to get a clone:

```bash
git clone https://github.com/amosavian/AMSMB2
```

You can update your library using this command in AMSMB2 folder:

```bash
git pull
```

if you have a git based project, use this command in your project's directory to add this project as a submodule to your project:

```bash
git submodule add https://github.com/amosavian/AMSMB2
```

Then drop `AMSMB2.xcodeproj` to you Xcode workspace and add the framework to your Embeded Binaries in target.

## Usage

Just read inline help to find what each function does. It's straightforward. It's thread safe and any queue.

To do listing files in directory and file operations you must use this template:

```swift
import AMSMB2

class SMBClient {
    /// connect to: `smb://guest@XXX.XXX.XX.XX/share`
    
    let serverURL = URL(string: "smb://XXX.XXX.XX.XX")!
    let credential = URLCredential(user: "guest", password: "", persistence: URLCredential.Persistence.forSession)
    let share = "share"
    
    lazy private var client = AMSMB2(url: self.serverURL, credential: self.credential)!
    
    private func connect(handler: @escaping (Result<AMSMB2, Error>) -> Void) {
        // AMSMB2 can handle queueing connection requests
        client.connectShare(name: self.share) { error in
            if let error = error {
                handler(.failure(error))
            } else {
                handler(.success(self.client))
            }
        }
    }
    
    func listDirectory(path: String) {
        connect { result in
            switch result {
            case .success(let client):
                client.contentsOfDirectory(atPath: path) { result in
                    switch result {
                    case .success(let files):
                        for entry in files {
                            print("name:", entry[.nameKey] as! String,
                                  ", path:", entry[.pathKey] as! String,
                                  ", type:", entry[.fileResourceTypeKey] as! URLFileResourceType,
                                  ", size:", entry[.fileSizeKey] as! Int64,
                                  ", modified:", entry[.contentModificationDateKey] as! Date,
                                  ", created:", entry[.creationDateKey] as! Date)
                        }
                        
                    case .failure(let error):
                        print(error)
                    }
                }
                
            case .failure(let error):
                print(error)
            }
        }
    }
    
    func moveItem(path: String, to toPath: String) {
        self.connect { result in
            switch result {
            case .success(let client):
                client.moveItem(atPath: path, toPath: toPath) { error in
                    if let error = error {
                        print(error)
                    } else {
                        print("\(path) moved successfully.")
                    }
                    
                    // Disconnecting is optional, it will be called eventually
                    // when `AMSMB2` object is freed.
                    // You may call it explicitly to detect errors.
                    client.disconnectShare(completionHandler: { (error) in
                        if let error = error {
                            print(error)
                        }
                    })
                }
                
            case .failure(let error):
                print(error)
            }
        }
    }
}
```

## License

While source code shipped with project is MIT licensed, but it has static link to `libsmb2` which is `LGPL v2.1`, consequently the whole project becomes `LGPL v2.1`.

You **must** link this library dynamically to your app if you intend to distribute your app on App Store.

[cocoapods]: https://cocoapods.org/pods/AMSMB2
[swift-image]: https://img.shields.io/badge/swift-5.0-orange.svg
[swift-url]: https://swift.org/
[platform-image]: https://img.shields.io/cocoapods/p/AMSMB2.svg
[license-image]: https://img.shields.io/github/license/amosavian/AMSMB2.svg
[license-url]: LICENSE
[travis-image]: https://travis-ci.com/amosavian/AMSMB2.svg
[travis-url]: https://travis-ci.com/amosavian/AMSMB2
[release-url]: https://github.com/amosavian/AMSMB2/releases
[release-image]: https://img.shields.io/github/release/amosavian/AMSMB2.svg
[pod-release-image]: https://img.shields.io/cocoapods/v/AMSMB2.svg
[carthage-image]: https://img.shields.io/badge/Carthage-compatible-4BC51D.svg
[accio-image]: https://img.shields.io/badge/Accio-supported-0A7CF5.svg
[cocoapods-downloads]: https://img.shields.io/cocoapods/dt/AMSMB2.svg
[cocoapods-apps]: https://img.shields.io/cocoapods/at/AMSMB2.svg
