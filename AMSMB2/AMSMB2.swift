//
//  AMSMB2.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2

public typealias SimpleCompletionHandler = ((_ error: Error?) -> Void)?
public typealias SMB2ReadProgressHandler = ((_ bytes: Int64, _ total: Int64) -> Bool)?
public typealias SMB2WriteProgressHandler = ((_ bytes: Int64) -> Bool)?
private typealias CopyProgressHandler = ((_ bytes: Int64, _ soFar: Int64, _ total: Int64) -> Bool)?

/// Implements SMB2 File operations.
@objc @objcMembers
public class AMSMB2: NSObject, NSSecureCoding, Codable, NSCopying, CustomReflectable {
    fileprivate var context: SMB2Context?
    
    public let url: URL
    fileprivate let _domain: String
    fileprivate var _workstation: String
    fileprivate let _user: String
    fileprivate let _password: String
    fileprivate let q: DispatchQueue
    fileprivate var _timeout: TimeInterval
    
    fileprivate var connectedShare: String?
    fileprivate let connectLock = NSLock()
    fileprivate let operationLock = NSCondition()
    fileprivate var operationCount: Int = 0
    
    /**
     The timeout interval to use when doing an operation until getting response. Default value is 60 seconds.
     Set this to 0 or negative value in order to disable it.
     */
    @objc
    open var timeout: TimeInterval {
        get {
            return context?.timeout ?? _timeout
        }
        set {
            _timeout = newValue
            context?.timeout = newValue
        }
    }
    
    public override var debugDescription: String {
        var result: String = ""
        for (label, value) in customMirror.children {
            result.append("\(label ?? ""): \(value) ")
        }
        return result
    }
    
    public var customMirror: Mirror {
        var c: [(label: String?, value: Any)] = []
        
        c.append((label: "url", value: self.url))
        c.append((label: "isConnected", value: (context?.isConnected ?? false)))
        c.append((label: "timeout", value: _timeout))
        if _domain.isEmpty { c.append((label: "domain", value: _domain)) }
        if _workstation.isEmpty { c.append((label: "workstation", value: _workstation)) }
        c.append((label: "user", value: _user))
        if let connectedShare = connectedShare { c.append((label: "share", value: connectedShare)) }
        
        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
    
    /**
     Initializes a SMB2 class with given url and credential.
     
     - Note: For now, only user/password credential on NTLM servers are supported.
     
     - Important: A connection to a share must be established by connectShare(name:completionHandler:) before any operation.
     */
    @objc
    public init?(url: URL, domain: String = "", credential: URLCredential?) {
        guard url.scheme?.lowercased() == "smb", url.host != nil else {
            return nil
        }
        let hostLabel = url.host.map({ "_" + $0 }) ?? ""
        self.q = DispatchQueue(label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent)
        self.url = url
        
        var domain = domain
        var workstation: String = ""
        var user: String = "guest"
        
        if var undigestedUser = credential?.user ?? url.user {
            // Extract domain
            if domain.isEmpty && undigestedUser.components(separatedBy: ";").count == 2 {
                let comps = undigestedUser.components(separatedBy: ";")
                domain = comps[0]
                undigestedUser = comps[1]
            }
            
            let userComps = undigestedUser.components(separatedBy: "\\")
            switch userComps.count {
            case 1:
                user = userComps[0]
            case 2:
                workstation = userComps[0]
                user = userComps[1]
            default:
                break
            }
        }
        
        _domain = domain
        _workstation = workstation
        _user = user
        _password = credential?.password ?? ""
        _timeout = 60.0
        super.init()
    }
    
    public required init?(coder aDecoder: NSCoder) {
        guard let url = aDecoder.decodeObject(of: NSURL.self, forKey: "url") as URL? else {
            aDecoder.failWithError(CocoaError(.coderValueNotFound,
                                              userInfo: [NSLocalizedDescriptionKey: "URL is not set."]))
            return nil
        }
        guard url.scheme?.lowercased() == "smb", url.host != nil else {
            aDecoder.failWithError(CocoaError(.coderReadCorrupt,
                                              userInfo: [NSLocalizedDescriptionKey: "URL is not valid."]))
            return nil
        }
        
        let hostLabel = url.host.map({ "_" + $0 }) ?? ""
        self.q = DispatchQueue(label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent)
        self.url = url
        self._domain = aDecoder.decodeObject(of: NSString.self, forKey: "domain") as String? ?? ""
        self._workstation = aDecoder.decodeObject(of: NSString.self, forKey: "workstation") as String? ?? ""
        self._user = aDecoder.decodeObject(of: NSString.self, forKey: "user") as String? ?? "guest"
        self._password = aDecoder.decodeObject(of: NSString.self, forKey: "password") as String? ?? ""
        self._timeout = aDecoder.decodeDouble(forKey: "timeout")
        super.init()
    }
    
    open func encode(with aCoder: NSCoder) {
        aCoder.encode(url, forKey: "url")
        aCoder.encode(_domain, forKey: "domain")
        aCoder.encode(_workstation, forKey: "workstation")
        aCoder.encode(_user, forKey: "user")
        aCoder.encode(_password, forKey: "password")
        aCoder.encode(timeout, forKey: "timeout")
    }
    
    public static var supportsSecureCoding: Bool {
        return true
    }
    
    enum CodingKeys: CodingKey {
        case url, domain, workstation
        case user, password, timeout
    }
    
    public required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let url = try container.decode(URL.self, forKey: .url)
        guard url.scheme?.lowercased() == "smb" else {
            throw DecodingError.dataCorruptedError(forKey: CodingKeys.url, in: container, debugDescription: "URL is not smb.")
        }
        
        let hostLabel = url.host.map({ "_" + $0 }) ?? ""
        self.q = DispatchQueue(label: "smb2_queue\(hostLabel)", qos: .default, attributes: .concurrent)
        self.url = url
        self._domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? ""
        self._workstation = try container.decodeIfPresent(String.self, forKey: .workstation) ?? ""
        self._user = try container.decodeIfPresent(String.self, forKey: .user) ?? ""
        self._password = try container.decodeIfPresent(String.self, forKey: .password) ?? ""
        self._timeout = try container.decodeIfPresent(TimeInterval.self, forKey: .timeout) ?? 60
        super.init()
    }
    
    open func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(url, forKey: .url)
        try container.encode(_domain, forKey: .domain)
        try container.encode(_workstation, forKey: .workstation)
        try container.encode(_user, forKey: .user)
        try container.encode(_password, forKey: .password)
        try container.encode(timeout, forKey: .timeout)
    }
    
    open func copy(with zone: NSZone? = nil) -> Any {
        let new = AMSMB2(url: url, domain: _domain, credential: URLCredential(user: _user, password: _password, persistence: .forSession))!
        new._workstation = _workstation
        new.timeout = timeout
        return new
    }
    
    /**
     Connects to a share.
     */
    @objc(connectShareWithName:completionHandler:)
    open func connectShare(name: String, completionHandler: @escaping (_ error: Error?) -> Void) {
        func establishContext() throws {
            let context = try SMB2Context(timeout: self._timeout)
            self.context = context
            self.initContext(context)
            let server = url.host! + (url.port.map { ":\($0)" } ?? "")
            try context.connect(server: server, share: name, user: self._user)
            self.connectedShare = name
        }
        
        queue {
            do {
                self.connectLock.lock()
                defer { self.connectLock.unlock() }
                if self.context == nil || self.context?.fileDescriptor == -1 || self.connectedShare != name {
                    try establishContext()
                }
                
                // Workaround disgraceful disconnect issue (e.g. server timeout)
                do {
                    try self.context!.echo()
                } catch {
                    try establishContext()
                }
               
                completionHandler(nil)
            } catch {
                completionHandler(error)
            }
        }
    }
    
    /**
     Disconnects from a share.
     
     - Parameters:
       - gracefully: waits until all queued operations are done before disconnecting from server. Default value is false.
       - completionHandler: closure will be run after enumerating is completed.
     
     - Important: Disconnecting when an operation is in progress may cause disgraceful termination of operation.
     */
    @objc(disconnectShareGraceFully:completionHandler:)
    open func disconnectShare(gracefully: Bool = false, completionHandler: SimpleCompletionHandler = nil) {
        queue {
            do {
                self.connectLock.lock()
                defer { self.connectLock.unlock() }
                if gracefully {
                    self.operationLock.lock()
                    while self.operationCount > 0 {
                        self.operationLock.wait()
                    }
                    self.operationLock.unlock()
                }
                try self.context?.disconnect()
                self.context = nil
                self.connectedShare = nil
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Send echo to server. Use it to prevent timeout or check connectivity.
     */
    @objc(echoWithCompletionHandler:)
    open func echo(completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                try self.context?.echo()
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Enumerates shares' list on server.
     
     - Parameters:
       - enumerateHidden: enumrating special/administrative e.g. user directory in macOS or
           shares usually ends with `$`, e.g. `C$` or `admin$`.
       - completionHandler: closure will be run after enumerating is completed.
       - result: An array of shares' name and remark name. `name` element can be passed to `connectShare()` function.
           remark name is suitable for displaying shares to user, but it is sometimes empty.
     */
    open func listShares(enumerateHidden: Bool = false,
                         completionHandler: @escaping (_ result: Result<[(name: String, comment: String)], Error>) -> Void) {
        queue {
            do {
                // We use separate context because when a context connects to a tree, it won't connect to another tree.
                let context = try SMB2Context(timeout: self.timeout)
                self.initContext(context)
                
                // Connecting to Interprocess Communication share
                try context.connect(server: self.url.host!, share: "IPC$", user: self._user)
                defer {
                    try? context.disconnect()
                }
                
                var shares = try context.shareEnum()
                if enumerateHidden {
                    shares = shares.filter { $0.props.type == .diskTree }
                } else {
                    shares = shares.filter { !$0.props.isHidden && $0.props.type == .diskTree }
                }
                let result = shares.map { ($0.name, $0.comment) }
                completionHandler(.success(result))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
    
    /// Only for test case coverage
    func _swift_listShares(enumerateHidden: Bool = false,
                         completionHandler: @escaping (_ result: Result<[(name: String, comment: String)], Error>) -> Void) {
        queue {
            do {
                // We use separate context because when a context connects to a tree, it won't connect to another tree.
                let context = try SMB2Context(timeout: self.timeout)
                self.initContext(context)
                
                // Connecting to Interprocess Communication share
                try context.connect(server: self.url.host!, share: "IPC$", user: self._user)
                defer {
                    try? context.disconnect()
                }
                
                var shares = try context.shareEnumSwift(serverName: self.url.host!)
                if enumerateHidden {
                    shares = shares.filter { $0.props.type == .diskTree }
                } else {
                    shares = shares.filter { !$0.props.isHidden && $0.props.type == .diskTree }
                }
                let result = shares.map { ($0.name, $0.comment) }
                completionHandler(.success(result))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
    
    /**
     Enumerates directory contents in the give path.
     
     - Parameters:
       - atPath: path of directory to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - recursive: subdirectories will enumerated if `true`.
       - result: An array of `[URLResourceKey: Any]` which holds files' attributes. file name is stored in `.nameKey`.
     */
    open func contentsOfDirectory(atPath path: String, recursive: Bool = false,
                                  completionHandler: @escaping (_ result: Result<[[URLResourceKey: Any]], Error>) -> Void) {
        queue {
            completionHandler(.init(catching: {
                return try self.listDirectory(path: path, recursive: recursive)
            }))
        }
    }
    
    /**
     Returns a dictionary that describes the attributes of the mounted file system on which a given path resides.
     
     - Parameters:
       - forPath: Any pathname within the mounted file system.
       - completionHandler: closure will be run after fetching attributes is completed.
       - result: A dictionary object that describes the attributes of the mounted file system on which path resides.
           See _File-System Attribute Keys_ for a description of the keys available in the dictionary.
     */
    open func attributesOfFileSystem(forPath path: String,
                                     completionHandler: @escaping (_ result: Result<[FileAttributeKey: Any], Error>) -> Void) {
        queue {
            completionHandler(.init(catching: {
                let context = try self.tryContext()
                // This exactly matches implementation of Swift Foundation.
                let stat = try context.statvfs(path.canonical)
                var result = [FileAttributeKey: Any]()
                let blockSize = UInt64(stat.f_bsize)
                // NSNumber allows to cast to any number type, but it is unsafe to cast to types with lower bitwidth
                result[.systemNumber] = NSNumber(value: stat.f_fsid)
                if stat.f_blocks < UInt64.max / blockSize {
                    result[.systemSize] = NSNumber(value: blockSize * stat.f_blocks)
                    result[.systemFreeSize] = NSNumber(value: blockSize * stat.f_bavail)
                }
                result[.systemNodes] = NSNumber(value: stat.f_files)
                result[.systemFreeNodes] = NSNumber(value: stat.f_ffree)
                return result
            }))
        }
    }
    
    /**
     Returns the attributes of the item at given path.
     
     - Parameters:
       - atPath: path of file to be enumerated.
       - completionHandler: closure will be run after enumerating is completed.
       - result: An dictionary with `URLResourceKey` as key which holds file's attributes.
     */
    open func attributesOfItem(atPath path: String,
                               completionHandler: @escaping (_ result: Result<[URLResourceKey: Any], Error>) -> Void) {
        queue {
            completionHandler(.init(catching: {
                let context = try self.tryContext()
                let stat = try context.stat(path.canonical)
                var result = [URLResourceKey: Any]()
                let name = (path as NSString).lastPathComponent
                result[.nameKey] = name
                result[.pathKey] = (path as NSString).appendingPathComponent(name)
                self.populateResourceValue(&result, stat: stat)
                return result
            }))
        }
    }
    
    /**
     Creates a new directory at given path.
     
     - Parameters:
       - atPath: path of new directory to be created.
       - completionHandler: closure will be run after operation is completed.
     */
    @objc(createDirectoryAtPath:completionHandler:)
    open func createDirectory(atPath path: String, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                try context.mkdir(path)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Removes an existing directory at given path.
     
     - Parameters:
       - atPath: path of directory to be removed.
       - recursive: children items will be deleted if `true`.
       - completionHandler: closure will be run after operation is completed.
     */
    @objc(removeDirectoryAtPath:recursive:completionHandler:)
    open func removeDirectory(atPath path: String, recursive: Bool, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                
                if recursive {
                    // To delete directory recursively, first we list directory contents recursively,
                    // Then sort path descending which will put child files before containing directory,
                    // Then we will unlink/rmdir every entry.
                    //
                    // This block will only delete children of directory, the path itself will removed after if block.
                    let list = try self.listDirectory(path: path, recursive: true)
                    let sortedContents = list.sorted(by: {
                        guard let firstPath = $0.filePath, let secPath = $1.filePath else {
                            return false
                        }
                        return firstPath.localizedStandardCompare(secPath) == .orderedDescending
                    })
                    
                    for item in sortedContents {
                        guard let itemPath = item.filePath else { continue }
                        if item.fileType == URLFileResourceType.directory {
                            try context.rmdir(itemPath)
                        } else {
                            try context.unlink(itemPath)
                        }
                    }
                }
                
                try context.rmdir(path)
                
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Removes an existing file at given path.
     
     - Parameters:
       - atPath: path of file to be removed.
       - completionHandler: closure will be run after operation is completed.
     */
    @objc(removeFileAtPath:completionHandler:)
    open func removeFile(atPath path: String, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                try context.unlink(path)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
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
    @objc(truncateFileAtPath:atOffset:completionHandler:)
    open func truncateFile(atPath path: String, atOffset: UInt64, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                try context.truncate(path, toLength: atOffset)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Moves/Renames an existing file at given path to a new location.
     
     - Parameters:
       - atPath: path of file to be move.
       - toPath: new location of file.
       - completionHandler: closure will be run after operation is completed.
     */
    @objc(moveItemAtPath:toPath:completionHandler:)
    open func moveItem(atPath path: String, toPath: String, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                try context.rename(path, to: toPath)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Fetches whole data contents of a file. With reporting progress on about every 1MiB.
     
     - Parameters:
       - atPath: path of file to be fetched.
       - progress: reports progress of recieved bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - bytes: recieved bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
       - result: a `Data` object which contains file contents.
     */
    open func contents(atPath path: String, progress: SMB2ReadProgressHandler,
                                           completionHandler: @escaping (_ result: Result<Data, Error>) -> Void) {
        contents(atPath: path, range: 0..<Int64.max, progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Fetches data contents of a file from an offset with specified length. With reporting progress
     on about every 1MiB.
     
     - Note: If range's lowerBound is bigger than file's size, an empty `Data` will be returned.
             If range's length exceeds file, returned data will be truncated to entire file content from given offset.
     
     - Parameters:
       - atPath: path of file to be fetched.
       - range: byte range that should be read, default value is whole file. e.g. `..<10` will read first ten bytes.
       - progress: reports progress of recieved bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - bytes: recieved bytes count.
       - total: expected content length.
       - completionHandler: closure will be run after reading data is completed.
       - result: a `Data` object which contains file contents.
     */
    open func contents<R: RangeExpression>(atPath path: String, range: R? = nil, progress: SMB2ReadProgressHandler,
                                           completionHandler: @escaping (_ result: Result<Data, Error>) -> Void)
        where R.Bound: FixedWidthInteger
    {
        let range: Range<R.Bound> = range?.relative(to: 0..<R.Bound.max) ?? 0..<R.Bound.max
        let lower = Int64(exactly: range.lowerBound) ?? (Int64.max - 1)
        let upper = Int64(exactly: range.upperBound) ?? Int64.max
        let int64Range = lower..<upper
        
        queue {
            completionHandler(.init(catching: { () -> Data in
                guard !int64Range.isEmpty else {
                    return Data()
                }
                
                let stream = OutputStream.toMemory()
                try self.read(path: path, range: int64Range, to: stream, progress: progress)
                guard let data = stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
                    throw POSIXError(.ENOMEM, description: "Data missed from stream")
                }
                return data
            }))
        }
    }
    
    /**
     Streams data contents of a file from an offset with specified length. With reporting data and progress
     on about every 1MiB.
     
     - Parameters:
       - atPath: path of file to be fetched.
       - offset: first byte of file to be read, starting from zero.
       - fetchedData: returns data portion fetched and recieved bytes count read and expected content length.
           User must return `true` if they want to continuing or `false` to abort reading.
       - offset: offset of first byte of data portion in file.
       - total: expected content length.
       - data: data portion which read from server.
       - completionHandler: closure will be run after reading data is completed.
     */
    @objc(contentsAtPath:fromOffset:fetchedData:completionHandler:)
    open func contents(atPath path: String, offset: Int64 = 0,
                       fetchedData: @escaping ((_ offset: Int64, _ total: Int64, _ data: Data) -> Bool),
                       completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                let context = try self.tryContext()
                let file = try SMB2FileHandle(forReadingAtPath: path, on: context)
                let size = try Int64(file.fstat().smb2_size)
                
                var shouldContinue = true
                try file.lseek(offset: offset, whence: .set)
                while shouldContinue {
                    let offset = try file.lseek(offset: 0, whence: .current)
                    let data = try file.read()
                    if data.isEmpty {
                        break
                    }
                    shouldContinue = fetchedData(offset, size, data)
                }
                
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Creates and writes data to file. With reporting progress on about every 1MiB.
     
     - Note: Data saved in server maybe truncated when completion handler returns error.
     
     - Parameters:
       - data: data that must be written to file. You can pass either `Data`, `[UInt8]` or `NSData` object.
       - toPath: path of file to be written.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    open func write<DataType: DataProtocol>(data: DataType, toPath path: String, progress: SMB2WriteProgressHandler,
                                            completionHandler: SimpleCompletionHandler) {
        self.write(stream: InputStream(data: Data(data)), toPath: path,
                   progress: progress, completionHandler: completionHandler)
    }
    
    /**
     Creates and writes input stream to file. With reporting progress on about every 1MiB.
     
     - Note: Data saved in server maybe truncated when completion handler returns error.
     
     - Important: Stream will be closed eventually if is not already opened when passed.
     
     - Parameters:
       - stream: input stream that provides data to be written to file.
       - toPath: path of file to be written.
       - chunkSize: optimized chunk size to read from stream. Default value is abount 1MB.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort writing.
       - bytes: written bytes count.
       - completionHandler: closure will be run after writing is completed.
     */
    @objc(writeStream:toPath:chunkSize:progress:completionHandler:)
    open func write(stream: InputStream, toPath path: String, chunkSize: Int = 0, progress: SMB2WriteProgressHandler,
                    completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                try self.write(from: stream, toPath: path, chunkSize: chunkSize, progress: progress)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Copy file contents to a new location. With reporting progress on about every 1MiB.
     
     - Note: This operation consists downloading and uploading file.
     
     - Parameters:
       - atPath: path of file to be copied from.
       - toPath: path of new file to be copied to.
       - recursive: copies directory structure and files if path is directory.
       - progress: reports progress of written bytes count so far and expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - bytes: written bytes count.
       - completionHandler: closure will be run after copying is completed.
     */
    @available(*, deprecated, message: "New method does server-side copy and is much faster.",
               renamed: "copyItem(atPath:toPath:recursive:progress:completionHandler:)")
    @objc(copyContentsOfItemAtPath:toPath:recursiveprogress::completionHandler:)
    open func copyContentsOfItem(atPath path: String, toPath: String, recursive: Bool,
                                 progress: SMB2ReadProgressHandler, completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                try self.recursiveCopyIterator(atPath: path, toPath: toPath, recursive: recursive, progress: progress,
                                               handle: self.copyContentsOfFile(atPath:toPath:progress:))
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
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
    @objc(copyItemAtPath:toPath:recursive:progress:completionHandler:)
    open func copyItem(atPath path: String, toPath: String, recursive: Bool, progress: SMB2ReadProgressHandler,
                       completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                try self.recursiveCopyIterator(atPath: path, toPath: toPath, recursive: recursive, progress: progress,
                                               handle: self.copyFile(atPath:toPath:progress:))
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Uploads local file contents to a new location. With reporting progress on about every 1MiB.
     
     - Note: given url must be local file url otherwise it will throw error.
     
     - Parameters:
       - at: url of a local file to be uploaded from.
       - toPath: path of new file to be uploaded to.
       - progress: reports progress of written bytes count so far.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    @objc(uploadItemAtURL:toPath:progress:completionHandler:)
    open func uploadItem(at url: URL, toPath: String, progress: SMB2WriteProgressHandler,
                         completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                guard try url.checkResourceIsReachable(), url.isFileURL, let stream = InputStream(url: url) else {
                    throw POSIXError(.EIO, description: "Could not create Stream from given URL, or given URL is not a local file.")
                }
                
                try self.write(from: stream, toPath: toPath, progress: progress)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
    
    /**
     Downloads file contents to a local url. With reporting progress on about every 1MiB.
     
     - Note: if a file already exists on given url, This function will overwrite to that url.
     
     - Note: given url must be local file url otherwise it will throw error.
     
     - Parameters:
       - atPath: path of file to be downloaded from.
       - at: url of a local file to be written to.
       - progress: reports progress of written bytes count so farand expected length of contents.
           User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    @objc(downloadItemAtPath:toURL:progress:completionHandler:)
    open func downloadItem(atPath path: String, to url: URL, progress: SMB2ReadProgressHandler,
                           completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                guard url.isFileURL, let stream = OutputStream(url: url, append: false) else {
                    throw POSIXError(.EIO, description: "Could not create Stream from given URL, or given URL is not a local file.")
                }
                try self.read(path: path, to: stream, progress: progress)
                completionHandler?(nil)
            } catch {
                try? FileManager.default.removeItem(at: url)
                completionHandler?(error)
            }
        }
    }
    
    /**
     Downloads file contents to a local url. With reporting progress on about every 1MiB.
     
     - Note: if a file already exists on given url, This function will overwrite to that url.
     
     - Note: given url must be local file url otherwise it will throw error.
     
     - Important: Stream will be closed eventually if is not alrady opened.
     
     - Parameters:
       - atPath: path of file to be downloaded from.
       - at: url of a local file to be written to.
       - progress: reports progress of written bytes count so farand expected length of contents.
         User must return `true` if they want to continuing or `false` to abort copying.
       - completionHandler: closure will be run after uploading is completed.
     */
    @objc(downloadItemAtPath:toStream:progress:completionHandler:)
    open func downloadItem(atPath path: String, to stream: OutputStream, progress: SMB2ReadProgressHandler,
                           completionHandler: SimpleCompletionHandler) {
        queue {
            do {
                try self.read(path: path, to: stream, progress: progress)
                completionHandler?(nil)
            } catch {
                completionHandler?(error)
            }
        }
    }
}

extension AMSMB2 {
    fileprivate func queue(_ closure: @escaping () -> Void) {
        self.operationLock.lock()
        self.operationCount += 1
        self.operationLock.unlock()
        q.async {
            closure()
            self.operationLock.lock()
            self.operationCount -= 1
            self.operationLock.broadcast()
            self.operationLock.unlock()
        }
    }
    
    fileprivate func initContext(_ context: SMB2Context) {
        context.securityMode = [.enabled]
        context.domain = _domain
        context.workstation = _workstation
        context.user = _user
        context.password = _password
        context.timeout = _timeout
    }
    
    fileprivate func tryContext() throws -> SMB2Context {
        guard let context = self.context else {
            throw POSIXError.init(.ENOTCONN, description: "SMB2 server not connected.")
        }
        return context
    }
    
    fileprivate func populateResourceValue(_ dic: inout [URLResourceKey: Any], stat: smb2_stat_64) {
        dic[.fileSizeKey] = NSNumber(value: stat.smb2_size)
        dic[.linkCountKey] = NSNumber(value: stat.smb2_nlink)
        dic[.documentIdentifierKey] = NSNumber(value: stat.smb2_ino)
        
        switch Int32(stat.smb2_type) {
        case SMB2_TYPE_DIRECTORY:
            dic[.fileResourceTypeKey] = URLFileResourceType.directory
        case SMB2_TYPE_FILE:
            dic[.fileResourceTypeKey] = URLFileResourceType.regular
        default:
            dic[.fileResourceTypeKey] = URLFileResourceType.unknown
        }
        dic[.isDirectoryKey] = NSNumber(value: stat.smb2_type == SMB2_TYPE_DIRECTORY)
        dic[.isRegularFileKey] = NSNumber(value: stat.smb2_type == SMB2_TYPE_FILE)
        
        dic[.contentModificationDateKey] = Date(timespec(tv_sec: Int(stat.smb2_mtime), tv_nsec: Int(stat.smb2_mtime_nsec)))
        dic[.attributeModificationDateKey] = Date(timespec(tv_sec: Int(stat.smb2_ctime), tv_nsec: Int(stat.smb2_ctime_nsec)))
        dic[.contentAccessDateKey] = Date(timespec(tv_sec: Int(stat.smb2_atime), tv_nsec: Int(stat.smb2_atime_nsec)))
        dic[.creationDateKey] = Date(timespec(tv_sec: Int(stat.smb2_btime), tv_nsec: Int(stat.smb2_btime_nsec)))
    }
    
    fileprivate func listDirectory(path: String, recursive: Bool) throws -> [[URLResourceKey: Any]] {
        let context = try self.tryContext()
        var contents = [[URLResourceKey: Any]]()
        let dir = try SMB2Directory(path.canonical, on: context)
        for ent in dir {
            guard let name = String(utf8String: ent.name) else { continue }
            if [".", ".."].contains(name) { continue }
            var result = [URLResourceKey: Any]()
            result[.nameKey] = name
            result[.pathKey] = (path as NSString).appendingPathComponent(name)
            self.populateResourceValue(&result, stat: ent.st)
            contents.append(result)
        }
        
        if recursive {
            let subDirectories = contents.filter { $0.fileType == .directory }
            
            for subDir in subDirectories {
                guard let path = subDir.filePath else { continue }
                contents.append(contentsOf: try listDirectory(path: path, recursive: true))
            }
        }
        
        return contents
    }
    
    fileprivate func recursiveCopyIterator(atPath path: String, toPath: String, recursive: Bool, progress: SMB2ReadProgressHandler,
                                           handle: (_ path: String, _ toPath: String, _ progress: CopyProgressHandler) throws -> Bool) throws {
        let context = try self.tryContext()
        let stat = try context.stat(path)
        if stat.smb2_type == SMB2_TYPE_DIRECTORY {
            try context.mkdir(toPath)
            
            let list = try self.listDirectory(path: path, recursive: recursive)
            let sortedContents = list.sorted(by: {
                guard let firstPath = $0.filePath, let secPath = $1.filePath else {
                    return false
                }
                return firstPath.localizedStandardCompare(secPath) == .orderedAscending
            })
            
            let overallSize = list.reduce(0, { (result, value) -> Int64 in
                if value.fileType  == URLFileResourceType.regular {
                    return result + (value.fileSize ?? 0)
                } else {
                    return result
                }
            })
            
            var totalCopied: Int64 = 0
            for item in sortedContents {
                guard let itemPath = item.filePath else { continue }
                let destPath = itemPath.replacingOccurrences(of: path, with: toPath, options: .anchored)
                if item.fileType == URLFileResourceType.directory {
                    try context.mkdir(destPath)
                } else {
                    let shouldContinue = try handle(itemPath, destPath, {
                        (bytes, _, _) -> Bool in
                        totalCopied += bytes
                        return progress?(totalCopied, overallSize) ?? true
                    })
                    if !shouldContinue {
                        break
                    }
                }
            }
        } else {
            _ = try self.copyFile(atPath: path, toPath: toPath, progress: { (_, soFar, total) -> Bool in
                return progress?(soFar, total) ?? true
            })
        }
    }
    
    fileprivate func copyFile(atPath path: String, toPath: String, progress: CopyProgressHandler) throws -> Bool {
        let context = try tryContext()
        let fileSource = try SMB2FileHandle(forReadingAtPath: path, on: context)
        let size = try Int64(fileSource.fstat().smb2_size)
        let sourceKey: IOCtl.RequestResumeKey = try fileSource.fcntl(command: .srvRequestResumeKey)
        // TODO: Get chunk size from server
        let chunkSize = fileSource.optimizedWriteSize
        let chunkArray = stride(from: 0, to: UInt64(size), by: chunkSize).map {
            IOCtl.SrvCopyChunk(sourceOffset: $0, targetOffset: $0, length: min(UInt32(UInt64(size) - $0), UInt32(chunkSize)))
        }
        if (try? context.stat(toPath)) != nil {
            throw POSIXError(POSIXError.EEXIST, description: "File already exists.")
        }
        let fileCreate = try SMB2FileHandle(forCreatingIfNotExistsAtPath: toPath, on: context)
        fileCreate.close()
        let fileDest = try SMB2FileHandle(forUpdatingAtPath: toPath, on: context)
        var shouldContinue = true
        for chunk in chunkArray {
            let chunkCopy = IOCtl.SrvCopyChunkCopy(sourceKey: sourceKey.resumeKey, chunks: [chunk])
            try fileDest.fcntl(command: .srvCopyChunk, args: chunkCopy)
            shouldContinue = progress?(Int64(chunk.length), Int64(chunk.sourceOffset) + Int64(chunk.length), size) ?? true
            if !shouldContinue {
                break
            }
        }
        return shouldContinue
    }
    
    fileprivate func copyContentsOfFile(atPath path: String, toPath: String, progress: CopyProgressHandler) throws -> Bool {
        let context = try self.tryContext()
        let fileRead = try SMB2FileHandle(forReadingAtPath: path, on: context)
        let size = try Int64(fileRead.fstat().smb2_size)
        let fileWrite = try SMB2FileHandle(forCreatingAndWritingAtPath: toPath, on: context)
        var shouldContinue = true
        while shouldContinue {
            let data = try fileRead.read()
            let written = try fileWrite.write(data: data)
            let offset = try fileRead.lseek(offset: 0, whence: .current)
            
            shouldContinue = progress?(Int64(written), offset, size) ?? true
            shouldContinue = shouldContinue && !data.isEmpty
        }
        try fileWrite.fsync()
        return shouldContinue
    }
    
    fileprivate func read(path: String, range: Range<Int64> = 0..<Int64.max, to stream: OutputStream,
                      progress: SMB2ReadProgressHandler) throws {
        let context = try self.tryContext()
        let file = try SMB2FileHandle(forReadingAtPath: path, on: context)
        let filesize = try Int64(file.fstat().smb2_size)
        let length = range.upperBound - range.lowerBound
        let size = min(length, filesize - range.lowerBound)
        
        try stream.withOpenStream {
            var shouldContinue = true
            var sent: Int64 = 0
            try file.lseek(offset: range.lowerBound, whence: .set)
            while shouldContinue {
                let prefCount = Int(min(Int64(file.optimizedReadSize), Int64(size - sent)))
                guard prefCount > 0 else {
                    break
                }
                
                let data = try file.read(length: prefCount)
                if data.isEmpty {
                    break
                }
                let written = try stream.write(data)
                guard written == data.count else {
                    throw POSIXError(.EIO, description: "Inconsitency in reading from SMB file handle.")
                }
                sent += Int64(written)
                shouldContinue = progress?(sent, size) ?? true
            }
        }
    }
    
    fileprivate func write(from stream: InputStream, toPath: String, chunkSize: Int = 0, progress: SMB2WriteProgressHandler) throws {
        let context = try self.tryContext()
        
        if (try? context.stat(toPath)) != nil {
            throw POSIXError(POSIXError.EEXIST, description: "File already exists.")
        }
        let file = try SMB2FileHandle(forCreatingAndWritingAtPath: toPath, on: context)
        let chunkSize = chunkSize > 0 ? chunkSize : file.optimizedWriteSize
        var totalWritten: UInt64 = 0
        
        do {
            try stream.withOpenStream {
                while true {
                    var segment = try stream.readData(maxLength: chunkSize)
                    if segment.count == 0 {
                        break
                    }
                    totalWritten += UInt64(segment.count)
                    // For last part, we make it size equal with other chunks in order to prevent POLLHUP on some servers
                    if segment.count < file.optimizedWriteSize {
                        segment.count = file.optimizedWriteSize
                    }
                    let written = try file.write(data: segment)
                    if written != segment.count {
                        throw POSIXError(.EIO, description: "Inconsitency in writing to SMB file handle.")
                    }
                    
                    var offset = try file.lseek(offset: 0, whence: .current)
                    if offset > totalWritten {
                        offset = Int64(totalWritten)
                    }
                    if let shouldContinue = progress?(offset), !shouldContinue {
                        break
                    }
                }
            }
            
            try file.ftruncate(toLength: totalWritten)
            try file.fsync()
        } catch {
            try? context.unlink(toPath)
            throw error
        }
    }
}
