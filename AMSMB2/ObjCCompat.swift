//
//  ObjCCompat.swift
//  AMSMB2
//
//  Created by Amir Abbas on 4/27/19.
//  Copyright © 2019 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation

extension SMB2Manager {
    /**
     Connects to a share.

     - Parameters:
       - name: share name to connect.
       - completionHandler: closure will be run after enumerating is completed.

     */
    @available(swift, obsoleted: 1.0)
    @objc(connectShareWithName:completionHandler:)
    open func __connectShare(name: String, completionHandler: @Sendable @escaping (_ error: (any Error)?) -> Void) {
        connectShare(name: name, completionHandler: completionHandler)
    }

    /**
     Disconnects from a share.

     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @available(swift, obsoleted: 1.0)
    @objc(disconnectShare)
    open func __disconnectShare() {
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
    open func __disconnectShare(completionHandler: SimpleCompletionHandler) {
        disconnectShare(completionHandler: completionHandler)
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
    open func __destinationOfSymbolicLink(
        atPath path: String,
        completionHandler: @Sendable @escaping (_ destinationPath: String?, _ error: (any Error)?) -> Void
    ) {
        destinationOfSymbolicLink(atPath: path, completionHandler: convert(completionHandler))
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
    open func __contents(
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
    open func __write(
        data: Data, toPath path: String, progress: WriteProgressHandler,
        completionHandler: SimpleCompletionHandler
    ) {
        write(data: data, toPath: path, progress: progress, completionHandler: completionHandler)
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
