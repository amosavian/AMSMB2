//
//  ObjCCompat.swift
//  AMSMB2
//
//  Created by Amir Abbas on 4/27/19.
//  Copyright © 2019 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

#if canImport(Darwin)
import Foundation

extension SMB2Manager {
    /// SMB2 Share URL.
    @available(swift, obsoleted: 1.0)
    @objc(url)
    var __url: URL { url }
    
    /// The timeout interval to use when doing an operation until getting response. Default value is 60 seconds.
    /// Set this to 0 or negative value in order to disable it.
    @available(swift, obsoleted: 1.0)
    @objc(timeout)
    public var __timeout: TimeInterval {
        get {
            timeout
        }
        set {
            timeout = newValue
        }
    }
    
    /**
     Initializes a SMB2 class with given url and credential.

     - Note: For now, only user/password credential on NTLM servers are supported.

     - Important: A connection to a share must be established by `connectShare(name:completionHandler:)` before any operation.

     - Parameters:
       - url: SMB server's URL.
       - credential: Username and password.
     */
    @available(swift, obsoleted: 1.0)
    @objc
    public convenience init?(url: NSURL, credential: URLCredential?) {
        self.init(url: url as URL, credential: credential)
    }
    
    /**
     Initializes a SMB2 class with given url and credential.

     - Note: For now, only user/password credential on NTLM servers are supported.

     - Important: A connection to a share must be established by `connectShare(name:completionHandler:)` before any operation.

     - Parameters:
       - url: SMB server's URL.
       - domain: User's domain, if applicable
       - credential: Username and password.
     */
    @available(swift, obsoleted: 1.0)
    @objc
    public convenience init?(url: NSURL, domain: NSString, credential: URLCredential?) {
        self.init(url: url as URL, domain: domain as String, credential: credential)
    }
    
    /**
     Connects to a share.

     - Parameters:
       - name: share name to connect.
       - completionHandler: closure will be run after enumerating is completed.

     */
    @available(swift, obsoleted: 1.0)
    @objc(connectShareWithName:completionHandler:)
    public func __connectShare(name: String, completionHandler: @Sendable @escaping (_ error: (any Error)?) -> Void) {
        connectShare(name: name, completionHandler: completionHandler)
    }
    
    /**
     Connects to a share.

     - Parameters:
       - name: Share name to connect.
       - encrypted: Enables SMB3 encryption if `true`, it fails with error in case server does not support encryption.
       - completionHandler: closure will be run after enumerating is completed.
     */
    @objc(connectShareWithName:encrypted:completionHandler:)
    public func __connectShare(
        name: String, encrypted: Bool, completionHandler: @Sendable @escaping (_ error: (any Error)?) -> Void
    ) {
        connectShare(name: name, encrypted: encrypted, completionHandler: completionHandler)
    }

    /**
     Disconnects from a share.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @available(swift, obsoleted: 1.0)
    @objc(disconnectShare)
    public func __disconnectShare() {
        disconnectShare()
    }

    /**
     Disconnects from a share.

     - Parameters:
       - completionHandler: closure will be run after enumerating is completed.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @available(swift, obsoleted: 1.0)
    @objc(disconnectShareWithCompletionHandler:)
    public func __disconnectShare(completionHandler: SimpleCompletionHandler) {
        disconnectShare(completionHandler: completionHandler)
    }
    
    /**
     Disconnects from a share.

     - Parameters:
       - gracefully: waits until all queued operations are done before disconnecting from server. Default value is `false`.
       - completionHandler: closure will be run after enumerating is completed.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @objc(disconnectShareGracefully:completionHandler:)
    public func __disconnectShare(
        gracefully: Bool, completionHandler: SimpleCompletionHandler
    ) {
        disconnectShare(gracefully: gracefully, completionHandler: completionHandler)
    }
    
    /**
     Sends echo to server. Use it to prevent timeout or check connectivity.

     - Parameter completionHandler: closure will be run after echoing server is completed.
     */
    @objc(echoWithCompletionHandler:)
    public func __echo(completionHandler: SimpleCompletionHandler) {
        echo(completionHandler: completionHandler)
    }
    
    /**
     Enumerates shares' list on server.

     - Parameters:
       - completionHandler: closure will be run after enumerating is completed.
       - names: An array of share names. Can be passed to `connectShare:` function.
       - comments: An array of share remark name, related to names array with same index. Suitable for displaying shares to user.
       - error: `NSError` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(listSharesWithCompletionHandler:)
    public func __listShares(
        completionHandler: @Sendable @escaping (_ names: [String], _ comments: [String], _ error: (any Error)?) -> Void
    ) {
        listShares(enumerateHidden: false) { result in
            switch result {
            case .success(let shares):
                completionHandler(shares.map(\.name), shares.map(\.comment), nil)
            case .failure(let error):
                completionHandler([], [], error)
            }
        }
    }

    /**
     Enumerates shares' list on server.

     - Parameters:
       - enumerateHidden: enumerating special/administrative e.g. user directory in macOS or
           shares usually ends with `$`, e.g. `C$` or `admin$`.
       - completionHandler: closure will be run after enumerating is completed.
       - names: An array of share names. Can be passed to `connectShare:` function.
       - comments: An array of share remark name, related to names array with same index. Suitable for displaying shares to user.
       - error: `Error` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(listSharesWithEnumerateHidden:completionHandler:)
    public func __listShares(
        enumerateHidden: Bool,
        completionHandler: @Sendable @escaping (_ names: [String], _ comments: [String], _ error: (any Error)?) -> Void
    ) {
        listShares(enumerateHidden: enumerateHidden) { result in
            switch result {
            case .success(let shares):
                completionHandler(shares.map(\.name), shares.map(\.comment), nil)
            case .failure(let error):
                completionHandler([], [], error)
            }
        }
    }

    /**
     Enumerates directory contents in the give path.

     - Parameters:
       - atPath: path of directory to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - recursive: subdirectories will enumerated if `YES`.
       - contents: An array of `NSDictionary<NSURLResourceKey, NSObject>` which holds files' attributes. file name is stored in `NSURLResourceKeyNameKey`.
       - error: `NSError` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(contentsOfDirectoryAtPath:recursive:completionHandler:)
    public func __contentsOfDirectory(
        atPath path: String, recursive: Bool = false,
        completionHandler: @Sendable @escaping (_ contents: [[URLResourceKey: Any]]?, _ error: (any Error)?) -> Void
    ) {
        contentsOfDirectory(
            atPath: path, recursive: recursive, completionHandler: convert(completionHandler)
        )
    }

    /**
     Returns a dictionary that describes the attributes of the mounted file system on which a given path resides.

     - Parameters:
       - forPath: Any pathname within the mounted file system.
       - completionHandler: closure will be run after fetching attributes is completed.
       - attributes: A dictionary object that describes the attributes of the mounted file system on which path resides.
           See _File-System Attribute Keys_ for a description of the keys available in the dictionary.
       - error: `NSError` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(attributesOfFileSystemForPath:completionHandler:)
    public func __attributesOfFileSystem(
        forPath path: String,
        completionHandler: @Sendable @escaping (_ attributes: [FileAttributeKey: Any]?, _ error: (any Error)?) -> Void
    ) {
        attributesOfFileSystem(forPath: path, completionHandler: convert(completionHandler))
    }

    /**
     Returns the attributes of the item at given path.

     - Parameters:
       - atPath: path of file to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - file: A dictionary with `NSURLResourceKey` as key which holds file's attributes.
       - error: `NSError` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(attributesOfItemAtPath:completionHandler:)
    public func __attributesOfItem(
        atPath path: String,
        completionHandler: @Sendable @escaping (_ file: [URLResourceKey: Any]?, _ error: (any Error)?) -> Void
    ) {
        attributesOfItem(atPath: path, completionHandler: convert(completionHandler))
    }

    /**
     Returns the path of the item pointed to by a symbolic link.

     - Parameters:
       - atPath: The path of a file or directory.
       - completionHandler: closure will be run after reading link is completed.
       - destinationPath: A `NSString` object containing the path of the directory or file to which the symbolic link path refers.
                 If the symbolic link is specified as a relative path, that relative path is returned.
       - error: `NSError` if any occurred during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(destinationOfSymbolicLinkAtPath:completionHandler:)
    public func __destinationOfSymbolicLink(
        atPath path: String,
        completionHandler: @Sendable @escaping (_ destinationPath: String?, _ error: (any Error)?) -> Void
    ) {
        destinationOfSymbolicLink(atPath: path, completionHandler: convert(completionHandler))
    }
    
    /**
     Creates a new directory at given path.

     - Parameters:
       - atPath: path of new directory to be created.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(createDirectoryAtPath:completionHandler:)
    public func __createDirectory(atPath path: String, completionHandler: SimpleCompletionHandler) {
        createDirectory(atPath: path, completionHandler: completionHandler)
    }

    /**
     Removes an existing directory at given path.

     - Parameters:
       - atPath: path of directory to be removed.
       - recursive: children items will be deleted if `true`.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(removeDirectoryAtPath:recursive:completionHandler:)
    public func __removeDirectory(
        atPath path: String, recursive: Bool, completionHandler: SimpleCompletionHandler
    ) {
        removeDirectory(atPath: path, recursive: recursive, completionHandler: completionHandler)
    }
    
    /**
     Removes an existing file at given path.

     - Parameters:
       - atPath: path of file to be removed.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(removeFileAtPath:completionHandler:)
    public func __removeFile(atPath path: String, completionHandler: SimpleCompletionHandler) {
        removeFile(atPath: path, completionHandler: completionHandler)
    }
    
    /**
     Removes an existing file or directory at given path.

     - Parameters:
       - atPath: path of file or directory to be removed.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(removeItemAtPath:completionHandler:)
    public func __removeItem(atPath path: String, completionHandler: SimpleCompletionHandler) {
        removeItem(atPath: path, completionHandler: completionHandler)
    }
    
    /**
     Truncates or extends the file represented by the path to a specified offset within the file and
     puts the file pointer at that position.

     If the file is extended (if offset is beyond the current end of file), the added characters are null bytes.

     - Parameters:
       - atPath: path of file to be truncated.
       - atOffset: final size of truncated file.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(truncateFileAtPath:atOffset:completionHandler:)
    public func __truncateFile(
        atPath path: String, atOffset: UInt64, completionHandler: SimpleCompletionHandler
    ) {
        truncateFile(atPath: path, atOffset: atOffset, completionHandler: completionHandler)
    }
    
    /**
     Moves/Renames an existing file at given path to a new location.

     - Parameters:
       - atPath: path of file to be move.
       - toPath: new location of file.
       - completionHandler: closure will be run after operation is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(moveItemAtPath:toPath:completionHandler:)
    public func __moveItem(
        atPath path: String, toPath: String, completionHandler: SimpleCompletionHandler
    ) {
        moveItem(atPath: path, toPath: toPath, completionHandler: completionHandler)
    }

    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     on about every 1MiB.

     - Note: If offset is bigger than file's size, an empty `NSData` will be returned. If length exceeds file, returned data
         will be truncated to entire file content from given offset.

     - Parameters:
       - atPath: path of file to be fetched.
       - offset: first byte of file to be read, starting from zero.
       - length: length of bytes should be read from offset.
       - progress: reports progress of received bytes count read and expected content length.
           User must return `YES` if they want to continuing or `NO` to abort reading.
       - bytes: received bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
       - contents: a `NSData` object which contains file contents.
       - error: `NSError` if any occurred during reading.
     */
    @available(swift, obsoleted: 1.0)
    @objc(contentsAtPath:fromOffset:toLength:progress:completionHandler:)
    public func __contents(
        atPath path: String, offset: Int64 = 0, length: Int = -1, progress: ReadProgressHandler,
        completionHandler: @Sendable @escaping (_ contents: Data?, _ error: (any Error)?) -> Void
    ) {
        guard offset >= 0 else {
            let error = POSIXError(.EINVAL, description: "Invalid content offset.")
            completionHandler(nil, error)
            return
        }

        let range = length >= 0 ? offset..<(offset + Int64(length)) : offset..<Int64.max
        contents(
            atPath: path, range: range, progress: progress,
            completionHandler: convert(completionHandler)
        )
    }
    
    /**
     Streams data contents of a file from an offset with specified length. With reporting data and progress
     on about every 1MiB.

     - Parameters:
       - atPath: path of file to be fetched.
       - offset: first byte of file to be read, starting from zero.
       - fetchedData: returns data portion fetched and received bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - offset: offset of first byte of data portion in file.
       - total: expected content length.
       - data: data portion which read from server.
       - completionHandler: closure will be run after reading data is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(contentsAtPath:fromOffset:fetchedData:completionHandler:)
    public func __contents(
        atPath path: String, offset: Int64 = 0,
        fetchedData: @Sendable @escaping (_ offset: Int64, _ total: Int64, _ data: Data) -> Bool,
        completionHandler: SimpleCompletionHandler
    ) {
        contents(atPath: path, offset: offset, fetchedData: fetchedData, completionHandler: completionHandler)
    }
    
    /**
     Creates/Opens and writes data to file at given offset. With reporting progress on about every 1MiB.
     
     - Important: If file size is greater than offset, contents after offset shall be truncated.
         If file size is less than offset, file size will be increased to the offset first.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - offset: The offset that new data will be written to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(appendData:toPath:offset:progress:completionHandler:)
    public func __append(
        data: Data, toPath path: String, offset: Int64, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        append(data: data, toPath: path, offset: offset, progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Creates and writes data to file. With reporting progress on about every 1MiB.

     - Note: Data saved in server maybe truncated when completion handler returns error.

     - Parameters:
       - data: data that must be written to file.
       - toPath: path of file to be written.
       - progress: reports progress of written bytes count so far.
           User must return `YES` if they want to continuing or `NO` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(writeData:toPath:progress:completionHandler:)
    public func __write(
        data: Data, toPath path: String, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        write(data: data, toPath: path, progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Copy files to a new location. With reporting progress on about every 1MiB.

     - Parameters:
       - atPath: path of file to be copied from.
       - toPath: path of new file to be copied to.
       - recursive: copies directory structure and files if path is directory.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - bytes: written bytes count.
       - completionHandler: closure will be run after copying is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(copyItemAtPath:toPath:recursive:progress:completionHandler:)
    public func __copyItem(
        atPath path: String, toPath: String, recursive: Bool,
        progress: ReadProgressHandler, completionHandler: SimpleCompletionHandler
    ) {
        copyItem(atPath: path, toPath: toPath, recursive: recursive, progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Uploads local file contents to a new location. With reporting progress on about every 1MiB.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of new file to be uploaded to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
     */
    @available(swift, obsoleted: 1.0)
    @objc(uploadItemAtURL:toPath:progress:completionHandler:)
    public func __uploadItem(
        at url: URL, toPath: String, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        uploadItem(at: url, toPath: toPath, progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Downloads file contents to a local url. With reporting progress on about every 1MiB.

     - Note: if a file already exists on given url, This function will overwrite to that url.

     - Note: given url must be local file url otherwise it will throw error.

     - Parameters:
       - atPath: path of file to be downloaded from.
       - at: url of a local file to be written to.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(downloadItemAtPath:toURL:progress:completionHandler:)
    public func __downloadItem(
        atPath path: String, to url: URL, progress: ReadProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        downloadItem(atPath: path, to: url, progress: progress, completionHandler: completionHandler)
    }
}

extension SMB2Manager {
    private func convert<T>(_ resultCompletion: @Sendable @escaping (T?, (any Error)?) -> Void) -> (
        @Sendable (Result<T, any Error>) -> Void
    ) {
        { result in
            switch result {
            case .success(let val):
                resultCompletion(val, nil)
            case .failure(let error):
                resultCompletion(nil, error)
            }
        }
    }
}
#endif
