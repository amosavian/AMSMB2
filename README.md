# AMSMB2


This is small Swift library for iOS which wraps [libsmb2](https://github.com/sahlberg/libsmb2) and allows to connect a SMB2/3 share and do file operation.

## Install

To have latest updates with ease, use this command on terminal to get a clone:

```bash
git clone https://github.com/amosavian/AMSMB2
```

You can update your library using this command in AMSMB2 folder:

```bash
git pull
```

if you have a git based project, use this command in your projects directory to add this project as a submodule to your project:

```bash
git submodule add https://github.com/amosavian/AMSMB2
```

Then drop `AMSMB2.xcodeproj` to you Xcode workspace and add the framework to your Embeded Binaries in target.

## Usage

Just read inline help to find what each function does. It's straightforward.

**For now, operations are not realy async. Any operation will be queued to be performed after the previous operation is completed. Please create mulitple instances of `AMSMB2` in case you need real asynchronous performing.**

To do file operations you must use this template:

```swift
import AMSMB2

class SMBClient {
    func connect(handler: @escaping (_ client: AMSMB2?, _ error: Error?) -> Void) {
        let client = AMSMB2(url: self.serverURL, credential: self.credential)!
            client.connectShare(name: self.share) { error in
                handler(client, error)
            }
    }
    
    func moveItem(path: String, to toPath: String, completionHandler: ((_ error: Error?) -> Void)?) {
        self.connect { (client, error) in
            if let error = error {
                completionHandler?(error)
                return
            }
            
            client?.moveItem(atPath: path, toPath: toPath) { error in
                completionHandler?(error)
                client?.disconnectShare() // If your job is finished
            }
        }
    }
}
```

## License

While this library source code is MIT licensed, but it has static link to libsmb2 which is `LGPL v2.1`, consequently this library becomes `LGPL v2.1`.

You **must** link this library dynamically to your app if you intend to distribute your app on App Store.