//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2
import SMB2.Raw

/// Provides synchronous operation on SMB2
final class SMB2Context: CustomDebugStringConvertible, CustomReflectable {
    struct NegotiateSigning: OptionSet {
        var rawValue: UInt16
        
        static let enabled = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let required = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }
    
    typealias Version = smb2_negotiate_version
    
    var context: UnsafeMutablePointer<smb2_context>?
    private var _context_lock = NSLock()
    var timeout: TimeInterval
    
    init(timeout: TimeInterval) throws {
        guard let _context = smb2_init_context() else {
            throw POSIXError(.ENOMEM)
        }
        self.context = _context
        self.timeout = timeout
    }
    
    deinit {
        if isConnected {
            try? self.disconnect()
        }
        try? withThreadSafeContext { (context) in
            smb2_destroy_context(context)
        }
    }
    
    func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R) throws -> R {
        guard let context = self.context else {
            throw POSIXError(.ECONNABORTED, description: "No valid smb2 context is available.")
        }
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        return try handler(context)
    }
    
    public var debugDescription: String {
        var result: String = ""
        for (label, value) in customMirror.children {
            result.append("\(label ?? ""): \(value) ")
        }
        return result
    }
    
    public var customMirror: Mirror {
        var c: [(label: String?, value: Any)] = []
        if let context = self.context {
            c.append((label: "server", value: String(cString: context.pointee.server)))
            c.append((label: "securityMode", value: securityMode))
            if let clientGuid = clientGuid { c.append((label: "clientGuid", value: clientGuid)) }
            if let user = user { c.append((label: "user", value: user)) }
            c.append((label: "versuin", value: version))
        }
        c.append((label: "isConnected", value: isConnected))
        c.append((label: "timeout", value: timeout))
        
        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
}

// MARK: Setting manipulation
extension SMB2Context {
    var workstation: String? {
        get {
            return (self.context?.pointee.workstation).map(String.init(cString:))
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_workstation(context, newValue)
            }
        }
    }
    
    var domain: String? {
        get {
            return (self.context?.pointee.domain).map(String.init(cString:))
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_domain(context, newValue)
            }
        }
    }
    
    var user: String? {
        get {
            return (self.context?.pointee.user).map(String.init(cString:))
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_user(context, newValue)
            }
        }
    }
    
    var password: String? {
        get {
            return (self.context?.pointee.password).map(String.init(cString:))
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_password(context, newValue)
            }
        }
    }
    
    var securityMode: NegotiateSigning {
        get {
            return (self.context?.pointee.security_mode).flatMap(NegotiateSigning.init(rawValue:)) ?? []
        }
        set {
            try? withThreadSafeContext { (context) in
                smb2_set_security_mode(context, newValue.rawValue)
            }
        }
    }
    
    var clientGuid: UUID? {
        guard let guid = smb2_get_client_guid(context) else {
            return nil
        }
        let uuid = UnsafeRawPointer(guid).assumingMemoryBound(to: uuid_t.self).pointee
        return UUID(uuid: uuid)
    }
    
    var version: Version {
        return (self.context?.pointee.dialect).map { Version(rawValue: UInt32($0)) } ?? .any
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
        return smb2_get_fd(context)
    }
    
    var error: String? {
        let errorStr = smb2_get_error(context)
        return errorStr.flatMap(String.init(utf8String:))
    }
    
    func whichEvents() -> Int32 {
        return smb2_which_events(context)
    }
    
    func service(revents: Int32) throws {
        let result = try withThreadSafeContext { (context) in
            return smb2_service(context, revents)
        }
        if result < 0 {
            self._context_lock.lock()
            smb2_destroy_context(context)
            context = nil
            self._context_lock.unlock()
        }
        try POSIXError.throwIfError(result, description: error, default: .EINVAL)
    }
}

// MARK: Connectivity
extension SMB2Context {
    func connect(server: String, share: String, user: String) throws {
        try async_await(defaultError: .ECONNREFUSED) { (context, cbPtr) -> Int32 in
            smb2_connect_share_async(context, server, share, user, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func disconnect() throws {
        try withThreadSafeContext { (context) in
            smb2_free_all_dirs(context)
            smb2_free_all_fhs(context)
        }
        try async_await(defaultError: .ECONNREFUSED) { (context, cbPtr) -> Int32 in
            smb2_disconnect_share_async(context, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func echo() throws -> Void {
        if !isConnected {
            throw POSIXError(.ENOTCONN)
        }
        try async_await(defaultError: .ECONNREFUSED) { (context, cbPtr) -> Int32 in
            smb2_echo_async(context, SMB2Context.generic_handler, cbPtr)
        }
        return
    }
}

// MARK: DCE-RPC
extension SMB2Context {
    func shareEnum() throws -> [(name: String, props: ShareProperties, comment: String)] {
        let (_, cmddata) = try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_share_enum_async(context, SMB2Context.generic_handler, cbPtr)
        }
        
        guard let opaque = OpaquePointer(cmddata) else {
            throw POSIXError(.ENOENT)
        }
        
        let rep = UnsafeMutablePointer<srvsvc_netshareenumall_rep>(opaque)
        defer {
            smb2_free_data(context, rep)
        }
        return parseShareEnum(ctr1: rep.pointee.ctr.pointee.ctr1)
    }
    
    func shareEnumSwift(serverName: String) throws -> [(name: String, props: ShareProperties, comment: String)]
    {
        // Connection to server service.
        let srvsvc = try SMB2FileHandle(forPipe: "srvsvc", on: self)
        
        // Bind command
        _ = try srvsvc.write(data: MSRPC.srvsvcBindData())
        let recvBindData = try srvsvc.pread(offset: 0, length: 8192)
        try validateBindData(recvBindData)
        
        // NetShareEnum reqeust, Level 1 mean we need share name and remark.
        _ = try srvsvc.pwrite(data: MSRPC.requestNetShareEnumAll(server: serverName), offset: 0)
        let recvData = try srvsvc.pread(offset: 0)
        return try MSRPC.parseNetShareEnumAllLevel1(data: recvData)
    }
}

// MARK: File manipulation
extension SMB2Context {
    func stat(_ path: String) throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_stat_async(context, path, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func statvfs(_ path: String) throws -> smb2_statvfs {
        var st = smb2_statvfs()
        try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_statvfs_async(context, path, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func truncate(_ path: String, toLength: UInt64) throws {
        try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_truncate_async(context, path, toLength, SMB2Context.generic_handler, cbPtr)
        }
    }
}

// MARK: File operation
extension SMB2Context {
    func mkdir(_ path: String) throws {
        try async_await(defaultError: .EEXIST) { (context, cbPtr) -> Int32 in
            smb2_mkdir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func rmdir(_ path: String) throws {
        try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_rmdir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func unlink(_ path: String) throws {
        try async_await(defaultError: .ENOLINK) { (context, cbPtr) -> Int32 in
            smb2_unlink_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    func rename(_ path: String, to newPath: String) throws {
        try async_await(defaultError: .ENOENT) { (context, cbPtr) -> Int32 in
            smb2_rename_async(context, path, newPath, SMB2Context.generic_handler, cbPtr)
        }
    }
}

// MARK: Async operation handler
extension SMB2Context {
    private class CBData {
        var result: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
        var data: UnsafeMutableRawPointer? = nil
        var status: UInt32 {
            return UInt32(bitPattern: result)
        }
    }
    
    private func wait_for_reply(_ cb: inout CBData) throws {
        let startDate = Date()
        while !cb.isFinished {
            var pfd = pollfd()
            pfd.fd = fileDescriptor
            pfd.events = Int16(whichEvents())
            
            if poll(&pfd, 1, 1000) < 0, errno != EAGAIN {
                let code = POSIXErrorCode(rawValue: errno) ?? .EINVAL
                throw POSIXError(code, description: error)
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
    
    static let generic_handler: smb2_command_cb = async_handler(data: true, finishing: true)
    
    static func async_handler(data: Bool, finishing: Bool) -> smb2_command_cb {
        switch (data, finishing) {
        case (true, true):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
                cbdata.data = command_data
                cbdata.isFinished = true
            }
        case (true, false):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
                cbdata.data = command_data
            }
        case (false, true):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
                cbdata.isFinished = true
            }
        case (false, false):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
            }
        }
    }
    
    typealias AsyncAwaitHandler<R> = (_ context: UnsafeMutablePointer<smb2_context>, _ cbPtr: UnsafeMutableRawPointer) -> R
    
    @discardableResult
    func async_await(defaultError: POSIXError.Code, execute handler: AsyncAwaitHandler<Int32>)
        throws -> (result: Int32, data: UnsafeMutableRawPointer?)
    {
        var cb = CBData()
        
        let result = try withThreadSafeContext { (context) -> Int32 in
            return handler(context, &cb)
        }
        try POSIXError.throwIfError(result, description: error, default: .ECONNRESET)
        try wait_for_reply(&cb)
        let cbResult = cb.result
        try POSIXError.throwIfError(cbResult, description: error, default: defaultError)
        let data = cb.data
        return (cbResult, data)
    }
    
    @discardableResult
    func async_await_pdu(defaultError: POSIXError.Code, execute handler: AsyncAwaitHandler<UnsafeMutablePointer<smb2_pdu>?>)
        throws -> (status: UInt32, data: UnsafeMutableRawPointer?)
    {
        var cb = CBData()
        
        try withThreadSafeContext { (context) -> Void in
            guard let pdu = handler(context, &cb) else {
                throw POSIXError(.ENOMEM)
            }
            smb2_queue_pdu(context, pdu)
        }
        try wait_for_reply(&cb)
        let status = cb.status
        if status & SMB2_STATUS_SEVERITY_MASK == SMB2_STATUS_SEVERITY_ERROR {
            let errorNo = nterror_to_errno(status)
            try POSIXError.throwIfError(-errorNo, description: nil, default: defaultError)
        }
        let data = cb.data
        return (status, data)
    }
}

fileprivate extension SMB2Context {
    func parseShareEnum(ctr1: srvsvc_netsharectr1) -> [(name: String, props: ShareProperties, comment: String)] {
        var result = [(name: String, props: ShareProperties, comment: String)]()
        let array = Array(UnsafeBufferPointer(start: ctr1.array, count: Int(ctr1.count)))
        for item in array {
            let name = String(cString: item.name)
            let type = ShareProperties(rawValue: item.type)
            let comment = String(cString: item.comment)
            result.append((name: name, props: type, comment: comment))
        }
        return result
    }
    
    func validateBindData(_ recvBindData: Data) throws {
        // Bind command result is exactly 68 bytes here. 54 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData.count < 68 {
            throw POSIXError(.EBADMSG, description:  "Binding failure: Invalid size")
        }
        
        // These bytes contains Ack result, 30 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData[44] > 0 || recvBindData[45] > 0 {
            // Ack result is not acceptance (0x0000)
            let errorCode = recvBindData[44] + (recvBindData[45] << 8)
            let errorCodeString = String(errorCode, radix: 16, uppercase: false)
            throw POSIXError(.EBADMSG, description:  "Binding failure: \(errorCodeString)")
        }
    }
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

struct ShareProperties: RawRepresentable {
    enum ShareType: UInt32 {
        case diskTree
        case printQ
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
