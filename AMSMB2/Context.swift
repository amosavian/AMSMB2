//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

/// Provides synchronous operation on SMB2
final class SMB2Client: CustomDebugStringConvertible, CustomReflectable, @unchecked Sendable {
    var context: UnsafeMutablePointer<smb2_context>?
    private var _context_lock = NSRecursiveLock()
    var timeout: TimeInterval

    var minWriteSize: Int = 32 * 1024

    init(timeout: TimeInterval) throws {
        self.context = try smb2_init_context().unwrap()
        self.timeout = timeout
    }

    deinit {
        if isConnected {
            try? self.disconnect()
        }
        try? withThreadSafeContext { context in
            self.context = nil
            smb2_destroy_context(context)
        }
    }

    func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R)
        throws -> R
    {
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        return try handler(context.unwrap())
    }

    public var debugDescription: String {
        String(reflecting: self)
    }

    public var customMirror: Mirror {
        var c: [(label: String?, value: Any)] = []
        if context != nil {
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

extension SMB2Client {
    var workstation: String {
        get {
            (context?.pointee.workstation).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_workstation(context, newValue)
            }
        }
    }

    var domain: String {
        get {
            (context?.pointee.domain).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_domain(context, newValue)
            }
        }
    }

    var user: String {
        get {
            (context?.pointee.user).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_user(context, newValue)
            }
        }
    }

    var password: String {
        get {
            (context?.pointee.password).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_password(context, newValue)
            }
        }
    }

    var securityMode: NegotiateSigning {
        get {
            (context?.pointee.security_mode).flatMap(NegotiateSigning.init(rawValue:)) ?? []
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_security_mode(context, newValue.rawValue)
            }
        }
    }

    var seal: Bool {
        get {
            context?.pointee.seal ?? 0 != 0
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_seal(context, newValue ? 1 : 0)
            }
        }
    }

    var authentication: Security {
        get {
            context?.pointee.sec ?? .undefined
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_authentication(context, .init(bitPattern: newValue.rawValue))
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
        context?.pointee.server.map(String.init(cString:))
    }

    var share: String? {
        context?.pointee.share.map(String.init(cString:))
    }

    var version: Version {
        (context?.pointee.dialect).map { Version(rawValue: UInt32($0)) } ?? .any
    }
    
    var passthrough: Bool {
        get {
            var result: Int32 = 0
            smb2_get_passthrough(context, &result)
            return result != 0
        }
        set {
            smb2_set_passthrough(context, newValue ? 1 : 0)
        }
    }

    var isConnected: Bool {
        fileDescriptor != -1
    }

    var fileDescriptor: Int32 {
        do {
            return try smb2_get_fd(context.unwrap())
        } catch {
            return -1
        }
    }

    var error: String? {
        smb2_get_error(context).map(String.init(cString:))
    }
    
    var ntError: NTStatus {
        .init(rawValue: smb2_get_nterror(context))
    }
    
    var errno: Int32 {
        ntError.posixErrorCode.rawValue
    }
    
    var maximumTransactionSize: Int {
        (context?.pointee.max_transact_size).map(Int.init) ?? 65535
    }

    func whichEvents() throws -> Int16 {
        try Int16(truncatingIfNeeded: smb2_which_events(context.unwrap()))
    }

    func service(revents: Int32) throws {
        let result = smb2_service(context, revents)
        if result < 0 {
            smb2_destroy_context(context)
            context = nil
            try POSIXError.throwIfError(result, description: error)
        }
    }
}

// MARK: Connectivity

extension SMB2Client {
    func connect(server: String, share: String, user: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_connect_share_async(
                context, server, share, user, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func disconnect() throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_free_all_dirs(context)
            smb2_free_all_fhs(context)
            return smb2_disconnect_share_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }

    func echo() throws {
        if !isConnected {
            throw POSIXError(.ENOTCONN)
        }
        try async_await { context, cbPtr -> Int32 in
            smb2_echo_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }
}

// MARK: DCE-RPC

extension SMB2Client {
    func shareEnum() throws -> [SMB2Share] {
        try async_await(dataHandler: [SMB2Share].init) { context, cbPtr -> Int32 in
            smb2_share_enum_async(context, SHARE_INFO_1, SMB2Client.generic_handler, cbPtr)
        }.data
    }

    func shareEnumSwift() throws -> [SMB2Share] {
        // Connection to server service.
        let srvsvc = try SMB2FileHandle(path: "srvsvc", desiredAccess: [.read, .write], createDisposition: .open, on: self)
        // Bind command
        _ = try srvsvc.write(data: MSRPC.SrvsvcBindData())
        let recvBindData = try srvsvc.pread(offset: 0, length: Int(Int16.max))
        try MSRPC.validateBindData(recvBindData)

        // NetShareEnum request, Level 1 mean we need share name and remark.
        _ = try srvsvc.pwrite(data: MSRPC.NetShareEnumAllRequest(serverName: server!), offset: 0)
        let recvData = try srvsvc.pread(offset: 0)
        return try MSRPC.NetShareEnumAllLevel1(data: recvData).shares
    }
}

// MARK: File information

extension SMB2Client {
    func stat(_ path: String) throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        try async_await { context, cbPtr -> Int32 in
            smb2_stat_async(context, path.canonical, &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }

    func statvfs(_ path: String) throws -> smb2_statvfs {
        var st = smb2_statvfs()
        try async_await { context, cbPtr -> Int32 in
            smb2_statvfs_async(context, path.canonical, &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }

    func readlink(_ path: String) throws -> String {
        try async_await(dataHandler: String.init) { context, cbPtr -> Int32 in
            smb2_readlink_async(context, path.canonical, SMB2Client.generic_handler, cbPtr)
        }.data
    }
    
    func symlink(_ path: String, to destination: String) throws {
        let file = try SMB2FileHandle(path: path, flags: O_RDWR | O_CREAT | O_EXCL | O_SYMLINK | O_SYNC, on: self)
        let reparse = IOCtl.SymbolicLinkReparse(path: destination, isRelative: true)
        try file.fcntl(command: .setReparsePoint, args: reparse)
    }
}

// MARK: File operation

extension SMB2Client {
    func mkdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_mkdir_async(context, path.canonical, SMB2Client.generic_handler, cbPtr)
        }
    }

    func rmdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rmdir_async(context, path.canonical, SMB2Client.generic_handler, cbPtr)
        }
    }

    func unlink(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_unlink_async(context, path.canonical, SMB2Client.generic_handler, cbPtr)
        }
    }
    
    private func unlinkSymlink(_ path: String) throws {
        let file = try SMB2FileHandle(path: path, flags: O_RDWR | O_SYMLINK, on: self)
        var inputBuffer = [UInt8](repeating: 0, count: 8)
        inputBuffer[0] = 0x01 // DeletePending set to true
        try withExtendedLifetime(file) { file in
            try inputBuffer.withUnsafeMutableBytes { buf in
                var req = smb2_set_info_request(
                    info_type: UInt8(SMB2_0_INFO_FILE),
                    file_info_class: UInt8(SMB2_FILE_DISPOSITION_INFORMATION),
                    buffer_length: UInt32(buf.count),
                    buffer_offset: 0,
                    additional_information: 0,
                    file_id: file.fileId.uuid,
                    input_data: buf.baseAddress
                )
                
                try async_await_pdu(dataHandler: EmptyReply.init) {
                    context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
                    smb2_cmd_set_info_async(context, &req, SMB2Client.generic_handler, cbPtr)
                }
            }
        }
    }
    
    func unlink(_ path: String, type: smb2_stat_64.ResourceType = .file) throws {
        switch type {
        case .directory:
            throw POSIXError(.EINVAL, description: "Use rmdir() to delete a directory.")
        case .file:
            try unlink(path)
        case .link:
            try unlinkSymlink(path)
        default:
            preconditionFailure("Not supported file type.")
        }
    }

    func rename(_ path: String, to newPath: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rename_async(
                context, path.canonical, newPath.canonical, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func truncate(_ path: String, toLength: UInt64) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_truncate_async(
                context, path.canonical, toLength, SMB2Client.generic_handler, cbPtr
            )
        }
    }
}

// MARK: Async operation handler

extension SMB2Client {
    private class CBData {
        var result: Int32 = .init(NTStatus.success.rawValue)
        var isFinished: Bool = false
        var dataHandler: ((UnsafeMutableRawPointer?) -> Void)?
        var status: NTStatus {
            NTStatus(rawValue: result)
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
            if NTStatus(rawValue: status) != .success {
                cbdata.result = status
            }
            cbdata.dataHandler?(command_data)
            cbdata.isFinished = true
        } catch {}
    }

    typealias ContextHandler<R> = (_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?)
        throws -> R
    typealias UnsafeContextHandler<R> = (
        _ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?
    ) throws -> R

    @discardableResult
    func async_await(execute handler: UnsafeContextHandler<Int32>) throws -> Int32 {
        try async_await(dataHandler: { _, _ in }, execute: handler).result
    }

    @discardableResult
    func async_await<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<Int32>
    )
        throws -> (result: Int32, data: DataType)
    {
        try withThreadSafeContext { context -> (Int32, DataType) in
            var cb = CBData()
            var resultData: DataType?
            var dataHandlerError: (any Error)?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(self, ptr)
                } catch {
                    dataHandlerError = error
                }
            }
            let result = try withUnsafeMutablePointer(to: &cb) { cb in
                try handler(context, cb)
            }
            try POSIXError.throwIfError(result, description: error)
            try wait_for_reply(&cb)
            let cbResult = cb.result

            try POSIXError.throwIfError(cbResult, description: error)
            if let error = dataHandlerError { throw error }
            return try (cbResult, resultData.unwrap())
        }
    }

    @discardableResult
    func async_await_pdu(execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>)
        throws -> UInt32
    {
        try async_await_pdu(dataHandler: { _, _ in }, execute: handler).status
    }

    @discardableResult
    func async_await_pdu<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>
    )
        throws -> (status: UInt32, data: DataType)
    {
        try withThreadSafeContext { context -> (UInt32, DataType) in
            var cb = CBData()
            var resultData: DataType?
            var dataHandlerError: (any Error)?
            cb.dataHandler = { ptr in
                do {
                    resultData = try dataHandler(self, ptr)
                } catch {
                    dataHandlerError = error
                }
            }
            let pdu = try withUnsafeMutablePointer(to: &cb) { cb in
                try handler(context, cb).unwrap()
            }
            smb2_queue_pdu(context, pdu)
            try wait_for_reply(&cb)

            try POSIXError.throwIfErrorStatus(cb.status)
            if let error = dataHandlerError { throw error }
            return try (cb.status.rawValue, resultData.unwrap())
        }
    }
}

extension SMB2Client {
    struct NegotiateSigning: OptionSet {
        var rawValue: UInt16

        static let enabled = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_ENABLED)
        static let required = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_REQUIRED)
    }

    typealias Version = smb2_negotiate_version
    typealias Security = smb2_sec
}

extension SMB2.smb2_negotiate_version: Swift.Hashable {
    static let any = SMB2_VERSION_ANY
    static let v2 = SMB2_VERSION_ANY2
    static let v3 = SMB2_VERSION_ANY3
    static let v2_02 = SMB2_VERSION_0202
    static let v2_10 = SMB2_VERSION_0210
    static let v3_00 = SMB2_VERSION_0300
    static let v3_02 = SMB2_VERSION_0302
    static let v3_11 = SMB2_VERSION_0311

    static func ==(lhs: smb2_negotiate_version, rhs: smb2_negotiate_version) -> Bool {
        lhs.rawValue == rhs.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}

extension SMB2.smb2_sec: Swift.Hashable {
    static let undefined = SMB2_SEC_UNDEFINED
    static let ntlmSsp = SMB2_SEC_NTLMSSP
    static let kerberos5 = SMB2_SEC_KRB5

    static func ==(lhs: smb2_sec, rhs: smb2_sec) -> Bool {
        lhs.rawValue == rhs.rawValue
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
        ShareType(rawValue: rawValue & 0x0fff_ffff)!
    }

    var isTemporary: Bool {
        rawValue & UInt32(bitPattern: SHARE_TYPE_TEMPORARY) != 0
    }

    var isHidden: Bool {
        rawValue & SHARE_TYPE_HIDDEN != 0
    }
}

struct NTStatus: LocalizedError, Hashable, Sendable {
    enum Severity: UInt32, Hashable, Sendable {
        case success
        case info
        case warning
        case error
        
        init(status: NTStatus) {
            self = switch status.rawValue & SMB2_STATUS_SEVERITY_MASK {
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_SUCCESS):
                .success
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_INFO):
                .info
            case SMB2_STATUS_SEVERITY_WARNING:
                .warning
            case SMB2_STATUS_SEVERITY_ERROR:
                .error
            default:
                .success
            }
        }
    }
    
    let rawValue: UInt32
    
    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    var errorDescription: String? {
        nterror_to_str(rawValue).map(String.init(cString:))
    }
    
    var posixErrorCode: POSIXErrorCode {
        .init(nterror_to_errno(rawValue))
    }
    
    var severity: Severity {
        .init(status: self)
    }
    
    static let success = Self(rawValue: SMB2_STATUS_SUCCESS)
}
