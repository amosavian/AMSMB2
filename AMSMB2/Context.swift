//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2
#if !SWIFT_PACKAGE
import SMB2.Raw
#endif

/// Provides synchronous operation on SMB2
final class SMB2Context: CustomDebugStringConvertible, CustomReflectable {
    var context: UnsafeMutablePointer<smb2_context>?
    private var _context_lock = NSRecursiveLock()
    var timeout: TimeInterval
    
    init(timeout: TimeInterval) throws {
        let _context = try smb2_init_context().unwrap()
        self.context = _context
        self.timeout = timeout
    }
    
    deinit {
        if isConnected {
            try? self.disconnect()
        }
        try? withThreadSafeContext { (context) in
            self.context = nil
            smb2_destroy_context(context)
        }
    }
    
    func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R) throws -> R {
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        return try handler(context.unwrap())
    }

    public var debugDescription: String {
        return String(reflecting: self)
    }
    
    public var customMirror: Mirror {
        var c: [(label: String?, value: Any)] = []
        if self.context != nil {
            c.append((label: "server", value: server!))
            c.append((label: "securityMode", value: securityMode))
            c.append((label: "authentication", value: authentication))
            clientGuid.map { c.append((label: "clientGuid", value: $0)) }
            c.append((label: "user", value: user))
            c.append((label: "version", value: version))
        }
        c.append((label: "isConnected", value: isConnected))
        c.append((label: "timeout", value: timeout))
        
        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
}

// MARK: Setting manipulation
extension SMB2Context {
    var workstation: String {
        get {
            return (context?.pointee.workstation).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_workstation(context, newValue)
            }
        }
    }
    
    var domain: String {
        get {
            return (context?.pointee.domain).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_domain(context, newValue)
            }
        }
    }
    
    var user: String {
        get {
            return (context?.pointee.user).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_user(context, newValue)
            }
        }
    }
    
    var password: String {
        get {
            return (context?.pointee.password).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_password(context, newValue)
            }
        }
    }
    
    var securityMode: NegotiateSigning {
        get {
            return (context?.pointee.security_mode).flatMap(NegotiateSigning.init(rawValue:)) ?? []
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_security_mode(context, newValue.rawValue)
            }
        }
    }
    
    var seal: Bool {
        get {
            return context?.pointee.seal ?? 0 != 0
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_seal(context, newValue ? 1 : 0)
            }
        }
    }
    
    var authentication: Security {
        get {
            return context?.pointee.sec ?? SMB2_SEC_UNDEFINED
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_authentication(context, Int32(bitPattern: newValue.rawValue))
            }
        }
    }
    
    var clientGuid: UUID? {
        guard let guid = try? smb2_get_client_guid(context.unwrap()) else {
            return nil
        }
        let uuid = UnsafeRawPointer(guid).assumingMemoryBound(to: uuid_t.self).pointee
        return UUID(uuid: uuid)
    }
    
    var server: String? {
        return context?.pointee.server.map(String.init(cString:))
    }
    
    var share: String? {
        return context?.pointee.share.map(String.init(cString:))
    }
    
    var version: Version {
        return (context?.pointee.dialect).map { Version(rawValue: UInt32($0)) } ?? .any
    }
    
    var isConnected: Bool {
        do {
            return try withThreadSafeContext { (context) -> Bool in
                context.pointee.is_connected != 0
            }
        } catch {
            return false
        }
    }
    
    var fileDescriptor: Int32 {
        return (try? smb2_get_fd(context.unwrap())) ?? -1
    }
    
    var error: String? {
        let errorStr = smb2_get_error(context)
        return errorStr.map(String.init(cString:))
    }
    
    func whichEvents() throws -> Int16 {
        return try Int16(truncatingIfNeeded: smb2_which_events(context.unwrap()))
    }
    
    func service(revents: Int32) throws {
        try withThreadSafeContext { (context) in
            let result = smb2_service(context, revents)
            if result < 0 {
                self.context = nil
                smb2_destroy_context(context)
            }
            try POSIXError.throwIfError(result, description: error)
        }
    }
}

// MARK: Connectivity
extension SMB2Context {
    func connect(server: String, share: String, user: String) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_connect_share_async(context, server, share, user, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func disconnect() throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_free_all_dirs(context)
            smb2_free_all_fhs(context)
            return smb2_disconnect_share_async(context, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func echo() throws -> Void {
        if !isConnected {
            throw POSIXError(.ENOTCONN)
        }
        try async_await { (context, cbPtr) -> Int32 in
            smb2_echo_async(context, SMB2Context.generic_handler, cbPtr)
        }
        return
    }
}

// MARK: DCE-RPC
extension SMB2Context {
    func shareEnum() throws -> [SMB2Share] {
        return try async_await(dataHandler: Parser.toSMB2Shares) { (context, cbPtr) -> Int32 in
            smb2_share_enum_async(context, SMB2Context.generic_handler, cbPtr)
        }.data
    }
    
    func shareEnumSwift() throws -> [SMB2Share]
    {
        // Connection to server service.
        let srvsvc = try SMB2FileHandle(path: "srvsvc", on: self)
        // Bind command
        _ = try srvsvc.write(data: MSRPC.srvsvcBindData())
        let recvBindData = try srvsvc.pread(offset: 0, length: Int(Int16.max))
        try MSRPC.validateBindData(recvBindData)
        
        // NetShareEnum reqeust, Level 1 mean we need share name and remark.
        _ = try srvsvc.pwrite(data: MSRPC.requestNetShareEnumAll(server: server!), offset: 0)
        let recvData = try srvsvc.pread(offset: 0)
        return try MSRPC.parseNetShareEnumAllLevel1(data: recvData)
    }
}

// MARK: File information
extension SMB2Context {
    func stat(_ path: String) throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        try async_await { (context, cbPtr) -> Int32 in
            smb2_stat_async(context, path, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func statvfs(_ path: String) throws -> smb2_statvfs {
        var st = smb2_statvfs()
        try async_await { (context, cbPtr) -> Int32 in
            smb2_statvfs_async(context, path, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func readlink(_ path: String) throws -> String {
        return try async_await(dataHandler: Parser.toString) { (context, cbPtr) -> Int32 in
            smb2_readlink_async(context, path, SMB2Context.generic_handler, cbPtr)
        }.data
    }
}

// MARK: File operation
extension SMB2Context {
    func mkdir(_ path: String) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_mkdir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func rmdir(_ path: String) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_rmdir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func unlink(_ path: String) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_unlink_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func rename(_ path: String, to newPath: String) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_rename_async(context, path, newPath, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func truncate(_ path: String, toLength: UInt64) throws {
        try async_await { (context, cbPtr) -> Int32 in
            smb2_truncate_async(context, path, toLength, SMB2Context.generic_handler, cbPtr)
        }
    }
}

// MARK: Async operation handler
extension SMB2Context {
    private class CBData {
        var result: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
        var dataHandler: ((UnsafeMutableRawPointer?) -> Void)? = nil
        var status: UInt32 {
            return UInt32(bitPattern: result)
        }
    }
    
    private func wait_for_reply(_ cb: inout CBData) throws {
        let startDate = Date()
        while !cb.isFinished {
            var pfd = pollfd()
            pfd.fd = fileDescriptor
            pfd.events = try whichEvents()
            
            if pfd.fd < 0 || (poll(&pfd, 1, 1000) < 0 && errno != EAGAIN) {
                throw POSIXError(.init(errno), description: error)
            }
            
            if pfd.revents == 0 {
                if timeout > 0, Date().timeIntervalSince(startDate) > timeout {
                    throw POSIXError(.ETIMEDOUT)
                }
                continue
            }
            
            try service(revents: Int32(pfd.revents))
        }
    }
    
    static let generic_handler: smb2_command_cb = { smb2, status, command_data, cbdata in
        do {
            guard try smb2.unwrap().pointee.fd >= 0 else { return }
            let cbdata = try cbdata.unwrap().bindMemory(to: CBData.self, capacity: 1).pointee
            if status != SMB2_STATUS_SUCCESS {
                cbdata.result = status
            }
            cbdata.dataHandler?(command_data)
            cbdata.isFinished = true
        } catch { }
    }
    
    typealias ContextHandler<R> = (_ context: UnsafeMutablePointer<smb2_context>, _ ptr: UnsafeMutableRawPointer?) throws -> R
    
    @discardableResult
    func async_await(execute handler: ContextHandler<Int32>) throws -> Int32
    {
        return try async_await(dataHandler: Parser.toVoid, execute: handler).result
    }
    
    @discardableResult
    func async_await<DataType>(dataHandler: @escaping ContextHandler<DataType>, execute handler: ContextHandler<Int32>)
        throws -> (result: Int32, data: DataType)
    {
        return try withThreadSafeContext { (context) -> (Int32, DataType) in
            var cb = CBData()
            var resultData: DataType?
            var dataHandlerError: Error?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(context, ptr)
                } catch {
                    dataHandlerError = error
                }
            }
            let result = try handler(context, &cb)
            try POSIXError.throwIfError(result, description: error)
            try wait_for_reply(&cb)
            let cbResult = cb.result
            
            try POSIXError.throwIfError(cbResult, description: error)
            if let error = dataHandlerError { throw error }
            return try (cbResult, resultData.unwrap())
        }
    }
    
    @discardableResult
    func async_await_pdu(execute handler: ContextHandler<UnsafeMutablePointer<smb2_pdu>?>) throws -> UInt32
    {
        return try async_await_pdu(dataHandler: Parser.toVoid, execute: handler).status
    }
    
    @discardableResult
    func async_await_pdu<DataType>(dataHandler: @escaping ContextHandler<DataType>, execute handler: ContextHandler<UnsafeMutablePointer<smb2_pdu>?>)
        throws -> (status: UInt32, data: DataType)
    {
        return try withThreadSafeContext { (context) -> (UInt32, DataType) in
            var cb = CBData()
            var resultData: DataType?
            var dataHandlerError: Error?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(context, ptr)
                } catch {
                    dataHandlerError = error
                }
            }
            let pdu = try handler(context, &cb).unwrap()
            smb2_queue_pdu(context, pdu)
            try wait_for_reply(&cb)
            let status = cb.status
            
            try POSIXError.throwIfErrorStatus(status)
            if let error = dataHandlerError { throw error }
            return try (status, resultData.unwrap())
        }
    }
}

extension SMB2Context {
    struct NegotiateSigning: OptionSet {
        var rawValue: UInt16
        
        static let enabled = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let required = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }
    
    typealias Version = smb2_negotiate_version
    typealias Security = smb2_sec
}

extension smb2_negotiate_version {
    static let any = SMB2_VERSION_ANY
    static let v2 = SMB2_VERSION_ANY2
    static let v3 = SMB2_VERSION_ANY3
    static let v2_02 = SMB2_VERSION_0202
    static let v2_10 = SMB2_VERSION_0210
    static let v3_00 = SMB2_VERSION_0300
    static let v3_02 = SMB2_VERSION_0302
    
    static func == (lhs: smb2_negotiate_version, rhs: smb2_negotiate_version) -> Bool {
        if lhs.rawValue == rhs.rawValue { return true }
        switch (lhs, rhs) {
        case (.any, _), (_, .any):
            return true
        case (.v2, v2_02), (v2_02, v2), (.v2, v2_10), (v2_10, v2):
            return true
        case (.v3, v3_00), (v3_00, v3), (.v3, v3_02), (v3_02, v3):
            return true
        default:
            return false
        }
    }
}

extension smb2_sec {
    static let undefined = SMB2_SEC_UNDEFINED
    static let ntlmSsp = SMB2_SEC_NTLMSSP
    static let kerberos5 = SMB2_SEC_KRB5
    
    static func == (lhs: smb2_sec, rhs: smb2_sec) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}

struct SMB2Share {
    let name: String
    let props: ShareProperties
    let comment: String
}

struct ShareProperties: RawRepresentable {
    enum ShareType: UInt32 {
        case diskTree
        case printQueue
        case device
        case ipc
    }
    
    let rawValue: UInt32
    
    var type: ShareType {
        return ShareType(rawValue: rawValue & 0x0fffffff)!
    }
    
    var isTemporary: Bool {
        return rawValue & UInt32(bitPattern: SHARE_TYPE_TEMPORARY) != 0
    }
    
    var isHidden: Bool {
        return rawValue & SHARE_TYPE_HIDDEN != 0
    }
}
