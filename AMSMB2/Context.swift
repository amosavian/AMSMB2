//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2

final class SMB2Context {
    struct NegotiateSigning: OptionSet {
        var rawValue: UInt16
        
        static let enabled = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED))
        static let required = NegotiateSigning(rawValue: UInt16(SMB2_NEGOTIATE_SIGNING_REQUIRED))
    }
    
    internal var context: UnsafeMutablePointer<smb2_context>
    var isConnected = false
    
    init?() {
        guard let _context = smb2_init_context() else {
            return nil
        }
        self.context = _context
    }
    
    deinit {
        if isConnected {
            try? self.disconnect()
        }
        smb2_destroy_context(context)
    }
}

// MARK: Setting manipulation
extension SMB2Context {
    func set(workstation value: String) {
        smb2_set_workstation(context, value)
    }
    
    func set(domain value: String) {
        smb2_set_domain(context, value)
    }
    
    func set(user value: String) {
        smb2_set_user(context, value)
    }
    
    func set(password value: String) {
        smb2_set_password(context, value)
    }
    
    func set(securityMode: NegotiateSigning) {
        smb2_set_security_mode(context, securityMode.rawValue)
    }
    
    func parseUrl(_ url: String) ->  UnsafeMutablePointer<smb2_url> {
        return smb2_parse_url(context, url)
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
        guard let errorStr = smb2_get_error(context) else {
            return nil
        }
        return String.init(utf8String: errorStr)
    }
    
    func whichEvents() -> Int32 {
        return smb2_which_events(context)
    }
    
    func service(revents: Int32) throws {
        let result = smb2_service(context, revents)
        try POSIXError.throwIfError(result, description: error, default: .EINVAL)
    }
}

// MARK: Connectivity
extension SMB2Context {
    func connect(server: String, share: String, user: String) throws {
        let result = smb2_connect_share(context, server, share, user)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
        self.isConnected = true
    }
    
    func disconnect() throws {
        let result = smb2_disconnect_share(context)
        self.isConnected = false
        try POSIXError.throwIfError(result, description: error, default: .ECONNABORTED)
    }
    
    func echo() throws -> Bool {
        let result = smb2_echo(context)
        try POSIXError.throwIfError(result, description: error, default: .ECONNREFUSED)
        return true
    }
}

// MARK: File manipulation
extension SMB2Context {
    func stat(_ path: String) throws -> smb2_stat_64 {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        var st = smb2_stat_64()
        let result = smb2_stat(context, cannonicalPath, &st)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
        return st
    }
    
    func statvfs(_ path: String) throws -> smb2_statvfs {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        var st = smb2_statvfs()
        let result = smb2_statvfs(context, cannonicalPath, &st)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
        return st
    }
    
    func truncate(_ path: String, toLength: UInt64) throws {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        let result = smb2_truncate(context, cannonicalPath, toLength)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
    }
}

// MARK: File operation
extension SMB2Context {
    func mkdir(_ path: String) throws {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        let result = smb2_mkdir(context, cannonicalPath)
        try POSIXError.throwIfError(result, description: error, default: .EEXIST)
    }
    
    func rmdir(_ path: String) throws {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        let result = smb2_rmdir(context, cannonicalPath)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
    }
    
    func unlink(_ path: String) throws {
        let result = smb2_rmdir(context, path)
        try POSIXError.throwIfError(result, description: error, default: .ENOLINK)
    }
    
    func rename(_ path: String, to newPath: String) throws {
        let cannonicalPath = path.replacingOccurrences(of: "/", with: "\\")
        let cannonicalNewPath = path.replacingOccurrences(of: "/", with: "\\")
        let (result, _) = try async_wait { (cbPtr) -> Int32 in
            smb2_rename_async(context, cannonicalPath, cannonicalNewPath, SMB2Context.async_handler, cbPtr)
        }
        
        try POSIXError.throwIfError(result, description: error, default: .ENOENT)
    }
}

// MARK: Async operation handler
extension SMB2Context {
    private struct CBData {
        var errNo: Int32  = 0
        var is_finished: Bool = false
        var commandData: UnsafeMutableRawPointer? = nil
        
        static var memSize: Int {
            return MemoryLayout<CBData>.size
        }
        
        static var memAlign: Int {
            return MemoryLayout<CBData>.alignment
        }
        
        static func initPointer() -> UnsafeMutableRawPointer {
            let cbPtr = UnsafeMutableRawPointer.allocate(byteCount: CBData.memSize, alignment: CBData.memAlign)
            cbPtr.initializeMemory(as: CBData.self, repeating: .init(), count: 1)
            return cbPtr
        }
    }
    
    private func wait_for_reply(_ cbPtr: UnsafeMutableRawPointer) throws {
        while !cbPtr.bindMemory(to: CBData.self, capacity: 1).pointee.is_finished {
            var pfd = pollfd()
            pfd.fd = fileDescriptor
            pfd.events = Int16(whichEvents())
            
            if poll(&pfd, 1, 1000) < 0 {
                try POSIXError.throwIfError(errno, description: error, default: .EINVAL)
            }
            
            if pfd.revents == 0 {
                continue
            }
            
            try service(revents: Int32(pfd.revents))
        }
    }
    
    static let async_handler: @convention(c) (_ smb2: UnsafeMutablePointer<smb2_context>?, _ status: Int32, _ command_data: UnsafeMutableRawPointer?, _ cbdata: UnsafeMutableRawPointer?) -> Void = { smb2, status, command_data, cbdata in
        cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee.errNo = status
        cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee.is_finished = true
        cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee.commandData = command_data
    }
    
    func async_wait(execute handler: (_ cbPtr: UnsafeMutableRawPointer) -> Int32) throws -> (result: Int32, data: UnsafeMutableRawPointer?) {
        let cbPtr = CBData.initPointer()
        defer {
            cbPtr.deallocate()
        }
        
        let result = handler(cbPtr)
        try wait_for_reply(cbPtr)
        let errNo = cbPtr.bindMemory(to: CBData.self, capacity: 1).pointee.errNo
        try POSIXError.throwIfError(errNo, description: error, default: .ECONNRESET)
        return (result, cbPtr.bindMemory(to: CBData.self, capacity: 1).pointee.commandData)
    }
}
