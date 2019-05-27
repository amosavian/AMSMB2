//
//  ObjCCompat.swift
//  AMSMB2
//
//  Created by Amir Abbas on 2/7/1398 AP.
//  Copyright © 1398 AP Mousavian. All rights reserved.
//

import Foundation

extension AMSMB2 {
    /**
     Disconnects from a share.
     
     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @objc(disconnectShare)
    open func __disconnectShare() {
        self.disconnectShare()
    }
    
    /**
     Disconnects from a share.
     
     - Parameters:
       - completionHandler: closure will be run after enumerating is completed.
     
     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @objc(disconnectShareWithCompletionHandler:)
    open func __disconnectShare(completionHandler: SimpleCompletionHandler) {
        self.disconnectShare(completionHandler: completionHandler)
    }
    
    /**
     Enumerates shares' list on server.
     
     - Parameters:
       - completionHandler: closure will be run after enumerating is completed.
       - names: An array of share names. Can be passed to `connectShare()` function.
       - comments: An array of share remark name, related to names array with same index. Suitable for displaying shares to user.
       - error: `Error` if any occured during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(listSharesWithCompletionHandler:)
    public func __listShares(completionHandler: @escaping (_ names: [String], _ comments: [String], _ error: Error?) -> Void) {
        listShares(enumerateHidden: false) { (result) in
            switch result {
            case .success(let shares):
                completionHandler(shares.map({ $0.name }), shares.map({ $0.comment }), nil)
            case .failure(let error):
                completionHandler([], [], error)
            }
        }
    }
    
    /**
     Enumerates shares' list on server.
     
     - Parameters:
       - enumerateHidden: enumrating special/administrative e.g. user directory in macOS or
           shares usually ends with `$`, e.g. `C$` or `admin$`.
       - completionHandler: closure will be run after enumerating is completed.
       - names: An array of share names. Can be passed to `connectShare()` function.
       - comments: An array of share remark name, related to names array with same index. Suitable for displaying shares to user.
       - error: `Error` if any occured during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(listSharesWithEnumerateHidden:completionHandler:)
    public func __listShares(enumerateHidden: Bool, completionHandler: @escaping (_ names: [String], _ comments: [String], _ error: Error?) -> Void) {
        listShares(enumerateHidden: enumerateHidden) { (result) in
            switch result {
            case .success(let shares):
                completionHandler(shares.map({ $0.name }), shares.map({ $0.comment }), nil)
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
       - recursive: subdirectories will enumerated if `true`.
       - contents: An array of `[URLResourceKey: Any]` which holds files' attributes. file name is stored in `.nameKey`.
       - error: `Error` if any occured during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(contentsOfDirectoryAtPath:recursive:completionHandler:)
    public func __contentsOfDirectory(atPath path: String, recursive: Bool = false,
                                      completionHandler: @escaping (_ contents: [[URLResourceKey: Any]]?, _ error: Error?) -> Void) {
        contentsOfDirectory(atPath: path, recursive: recursive, completionHandler: convert(completionHandler))
    }
    
    /**
     Returns a dictionary that describes the attributes of the mounted file system on which a given path resides.
     
     - Parameters:
       - forPath: Any pathname within the mounted file system.
       - completionHandler: closure will be run after fetching attributes is completed.
       - attrubutes: A dictionary object that describes the attributes of the mounted file system on which path resides.
           See _File-System Attribute Keys_ for a description of the keys available in the dictionary.
       - error: `Error` if any occured during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(attributesOfFileSystemForPath:completionHandler:)
    public func __attributesOfFileSystem(forPath path: String,
                                         completionHandler: @escaping (_ attrubutes: [FileAttributeKey: Any]?, _ error: Error?) -> Void) {
        attributesOfFileSystem(forPath: path, completionHandler: convert(completionHandler))
    }
    
    /**
     Returns the attributes of the item at given path.
     
     - Parameters:
       - atPath: path of file to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - file: An dictionary with `URLResourceKey` as key which holds file's attributes.
       - error: `Error` if any occured during enumeration.
     */
    @available(swift, obsoleted: 1.0)
    @objc(attributesOfItemAtPath:completionHandler:)
    public func __attributesOfItem(atPath path: String,
                                   completionHandler: @escaping (_ file: [URLResourceKey: Any]?, _ error: Error?) -> Void) {
        attributesOfItem(atPath: path, completionHandler: convert(completionHandler))
    }
    
    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     on about every 1MiB.
     
     - Note: If offset is bigger than file's size, an empty `Data` will be returned. If length exceeds file, returned data
         will be truncated to entire file content from given offset.
     
     - Parameters:
       - atPath: path of file to be fetched.
       - offset: first byte of file to be read, starting from zero.
       - length: length of bytes should be read from offset.
       - progress: reports progress of recieved bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - bytes: recieved bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
       - contents: a `Data` object which contains file contents.
       - error: `Error` if any occured during reading.
     */
    @available(swift, obsoleted: 1.0)
    @objc(contentsAtPath:fromOffset:toLength:progress:completionHandler:)
    open func __contents(atPath path: String, offset: Int64 = 0, length: Int = -1, progress: SMB2ReadProgressHandler,
                       completionHandler: @escaping (_ contents: Data?, _ error: Error?) -> Void) {
        guard offset >= 0 else {
            let error = POSIXError(.EINVAL, description: "Invalid content offset.")
            completionHandler(nil, error)
            return
        }
        
        let range = length >= 0 ? offset..<(offset + Int64(length)) : offset..<Int64.max
        contents(atPath: path, range: range, progress: progress, completionHandler: convert(completionHandler))
    }
    
    /**
     Creates and writes data to file. With reporting progress on about every 1MiB.
     
     - Note: Data saved in server maybe truncated when completion handler returns error.
     
     - Parameters:
       - data: data that must be written to file.
       - toPath: path of file to be written.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    @available(swift, obsoleted: 1.0)
    @objc(writeData:toPath:progress:completionHandler:)
    open func __write(data: Data, toPath path: String, progress: SMB2WriteProgressHandler,
                      completionHandler: SimpleCompletionHandler) {
        write(data: Data(data), toPath: path, progress: progress, completionHandler: completionHandler)
    }
}

extension AMSMB2 {
    fileprivate func convert<T>(_ resultCompletion: @escaping (T?, Error?) -> Void) -> ((Result<T, Error>) -> Void) {
        return { result in
            switch result {
            case .success(let val):
                resultCompletion(val, nil)
            case .failure(let error):
                resultCompletion(nil, error)
            }
        }
    }
}
