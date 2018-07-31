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

final class SMB2Context {
    struct NegotiateSigning: OptionSet {
        var rawValue: UInt16
        
        static let enabled = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let required = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }
    
    internal var context: UnsafeMutablePointer<smb2_context>
    private var _context_lock = NSLock()
    var isConnected = false
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
        withThreadSafeContext { (context) in
            smb2_destroy_context(context)
        }
    }
    
    internal func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R) rethrows -> R {
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        return try handler(self.context)
    }
}

// MARK: Setting manipulation
extension SMB2Context {
    func set(workstation value: String) {
        withThreadSafeContext { (context) in
            smb2_set_workstation(context, value)
        }
    }
    
    func set(domain value: String) {
        withThreadSafeContext { (context) in
            smb2_set_domain(context, value)
        }
    }
    
    func set(user value: String) {
        withThreadSafeContext { (context) in
            smb2_set_user(context, value)
        }
    }
    
    func set(password value: String) {
        withThreadSafeContext { (context) in
            smb2_set_password(context, value)
        }
    }
    
    func set(securityMode: NegotiateSigning) {
        withThreadSafeContext { (context) in
            smb2_set_security_mode(context, securityMode.rawValue)
        }
    }
    
    func parseUrl(_ url: String) throws -> UnsafeMutablePointer<smb2_url> {
        return try withThreadSafeContext { (context) in
            if let result = smb2_parse_url(context, url) {
                return result
            }
            
            let errorDescription = self.error
            switch errorDescription {
            case "URL does not start with 'smb://'":
                throw POSIXError(.ENOPROTOOPT, description: errorDescription)
            case "URL is too long":
                throw POSIXError(.EOVERFLOW, description: errorDescription)
            case "Failed to allocate smb2_url":
                throw POSIXError(.ENOMEM, description: errorDescription)
            default:
                throw POSIXError(.EINVAL, description: errorDescription)
            }
        }
    }
    
    var clientGuid: UUID? {
        guard let guid = smb2_get_client_guid(context) else {
            return nil
        }
        
        let uuid = guid.withMemoryRebound(to: uuid_t.self, capacity: 1) { ptr in
            return ptr.pointee
        }
        
        return UUID.init(uuid: uuid)
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
        let result = withThreadSafeContext { (context)  in
            return smb2_service(context, revents)
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
        self.isConnected = true
    }
    
    func disconnect() throws {
        try async_await(defaultError: .ECONNREFUSED) { (context, cbPtr) -> Int32 in
            smb2_disconnect_share_async(context, SMB2Context.generic_handler, cbPtr)
        }
        self.isConnected = false
    }
    
    @discardableResult
    func echo() throws -> Bool {
        try async_await(defaultError: .ECONNREFUSED) { (context, cbPtr) -> Int32 in
            smb2_echo_async(context, SMB2Context.generic_handler, cbPtr)
        }
        return true
    }
}

// MARK: DCE-RPC
extension SMB2Context {
    func shareEnum() throws -> [(name: String, type: UInt32, comment: String)] {
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
        
        var result = [(name: String, type: UInt32, comment: String)]()
        let array = Array(UnsafeBufferPointer(start: rep.pointee.ctr.pointee.ctr1.array, count: Int(rep.pointee.ctr.pointee.ctr1.count)))
        for item in array {
            let name = String(cString: item.name)
            let type = item.type
            let comment = String(cString: item.comment)
            result.append((name: name, type: type, comment: comment))
        }
        
        return result
    }
    
    func shareEnumSwift(serverName: String) throws -> [(name: String, type: UInt32, comment: String)]
    {
        // Connection to server service.
        let srvsvc = try SMB2FileHandle(forPipe: "srvsvc", on: self)
        
        // Sending bind command to DCE-RPC.
        _ = try srvsvc.write(data: MSRPC.srvsvcBindData())
        // Reading bind command result to DCE-RPC.
        let recvBindData = try srvsvc.pread(offset: 0, length: 8192)
        // Bind command result is exactly 68 bytes here. 54 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData.count < 68 {
            try POSIXError.throwIfError(Int32.min, description: "Binding failure", default: .EBADMSG)
        }
        
        // These bytes contains Ack result, 30 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData[44] > 0 || recvBindData[45] > 0 {
            // Ack result is not acceptance (0x0000)
            let errorCode = recvBindData[44] + (recvBindData[45] << 8)
            let errorCodeString = String(errorCode, radix: 16, uppercase: false)
            throw POSIXError(.EBADMSG, userInfo: [
                NSLocalizedFailureReasonErrorKey: "Binding failure: \(errorCodeString)"])
        }
        
        // Send NetShareEnum reqeust, Level 1 mean we need share name and remark.
        _ = try srvsvc.pwrite(data: MSRPC.requestNetShareEnumAll(server: serverName), offset: 0)
        // Reading NetShareEnum result.
        let recvData = try srvsvc.pread(offset: 0)
        // Parse result into Array.
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
        var commandData: UnsafeMutableRawPointer? = nil
        
        static func new() -> UnsafeMutablePointer<CBData> {
            let cbPtr = UnsafeMutablePointer<CBData>.allocate(capacity: 1)
            cbPtr.initialize(to: .init())
            return cbPtr
        }
    }
    
    private func wait_for_reply(_ cbPtr: UnsafeMutablePointer<CBData>) throws {
        let startDate = Date()
        while !cbPtr.pointee.isFinished {
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
    
    static let generic_handler = async_handler(data: true, finishing: true)
    
    static func async_handler(data: Bool, finishing: Bool) ->
        @convention(c) (UnsafeMutablePointer<smb2_context>?, Int32, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Void
    {
        switch (data, finishing) {
        case (true, true):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
                cbdata.commandData = command_data
                cbdata.isFinished = true
            }
        case (true, false):
            return { smb2, status, command_data, cbdata in
                guard let cbdata = cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee else { return }
                if status != SMB2_STATUS_SUCCESS {
                    cbdata.result = status
                }
                cbdata.commandData = command_data
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
    
    @discardableResult
    func async_await(defaultError: POSIXError.Code,
                     execute handler: (_ context: UnsafeMutablePointer<smb2_context>, _ cbPtr: UnsafeMutableRawPointer) -> Int32)
        throws -> (result: Int32, data: UnsafeMutableRawPointer?)
    {
        let cbPtr = CBData.new()
        defer {
            cbPtr.deallocate()
        }
        
        let result = withThreadSafeContext { (context) -> Int32 in
            return handler(context, cbPtr)
        }
        try POSIXError.throwIfError(result, description: error, default: .ECONNRESET)
        try wait_for_reply(cbPtr)
        let cbResult = cbPtr.pointee.result
        try POSIXError.throwIfError(cbResult, description: error, default: defaultError)
        let data = cbPtr.pointee.commandData
        return (cbResult, data)
    }
    
    func async_await_pdu(defaultError: POSIXError.Code,
                         execute handler: (_ context: UnsafeMutablePointer<smb2_context>, _ cbPtr: UnsafeMutableRawPointer) -> UnsafeMutablePointer<smb2_pdu>?)
        throws -> (result: UInt32, data: UnsafeMutableRawPointer?)
    {
        let cbPtr = CBData.new()
        defer {
            cbPtr.deallocate()
        }
        
        try withThreadSafeContext { (context) -> Void in
            let result = handler(context, cbPtr)
            guard let pdu = result else {
                throw POSIXError(.ENOMEM)
            }
            smb2_queue_pdu(context, pdu)
        }
        try wait_for_reply(cbPtr)
        let result = UInt32(bitPattern: cbPtr.pointee.result)
        if result & SMB2_STATUS_SEVERITY_ERROR == SMB2_STATUS_SEVERITY_ERROR {
            let errorNo = nterror_to_errno(result)
            try POSIXError.throwIfError(-errorNo, description: nil, default: defaultError)
        }
        let data = cbPtr.pointee.commandData
        return (result, data)
    }
}
