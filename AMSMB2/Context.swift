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
    enum NegotiateSigning: UInt16 {
        case enabled = 1
        case required = 2
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
}

// MARK: Connectivity
extension SMB2Context {
    func connect(server: String, share: String, user: String) throws {
        let result = smb2_connect_share(context, server, share, user)
        try POSIXError.throwIfError(result, default: .ENOLINK)
        self.isConnected = true
    }
    
    func disconnect() throws {
        let result = smb2_disconnect_share(context)
        self.isConnected = false
        try POSIXError.throwIfError(result, default: .ECONNABORTED)
    }
    
    func echo() throws -> Bool {
        let result = smb2_echo(context)
        try POSIXError.throwIfError(result, default: .ECONNREFUSED)
        return true
    }
}

// MARK: File manipulation
extension SMB2Context {
    func stat(_ path: String) throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        let result = smb2_stat(context, path, &st)
        try POSIXError.throwIfError(result, default: .ENOLINK)
        return st
    }
    
    func truncate(_ path: String, toLength: UInt64) throws {
        let result = smb2_truncate(context, path, toLength)
        try POSIXError.throwIfError(result, default: .ENOLINK)
    }
}

// MARK: File operation
extension SMB2Context {
    func mkdir(_ path: String) throws {
        let result = smb2_mkdir(context, path)
        try POSIXError.throwIfError(result, default: .EEXIST)
    }
    
    func rmdir(_ path: String) throws {
        let result = smb2_rmdir(context, path)
        try POSIXError.throwIfError(result, default: .ENOLINK)
    }
    
    func unlink(_ path: String) throws {
        let result = smb2_rmdir(context, path)
        try POSIXError.throwIfError(result, default: .ENOLINK)
    }
    
    func rename(_ path: String, to newPath: String) throws {
        let result = try async_wait { (cbPtr) -> Int32 in
            smb2_rename_async(context, path, newPath, SMB2Context.async_handler, cbPtr)
        }
        
        try POSIXError.throwIfError(result, default: .ENOENT)
    }
}

// MARK: Async operation handler
extension SMB2Context {
    private struct CBData {
        var errNo: Int32
        var is_finished: Bool
        
        static var memSize: Int {
            return MemoryLayout<CBData>.size
        }
        
        static var memAlign: Int {
            return MemoryLayout<CBData>.alignment
        }
        
        static func initPointer() -> UnsafeMutableRawPointer {
            let cbPtr = UnsafeMutableRawPointer.allocate(byteCount: CBData.memSize, alignment: CBData.memAlign)
            cbPtr.initializeMemory(as: CBData.self, repeating: .init(errNo: 0, is_finished: false), count: 1)
            return cbPtr
        }
    }
    
    private func wait_for_reply(_ cbPtr: UnsafeMutableRawPointer) -> Int {
        while !cbPtr.bindMemory(to: CBData.self, capacity: 1).pointee.is_finished {
            var pfd = pollfd()
            pfd.fd = smb2_get_fd(context)
            pfd.events = Int16(smb2_which_events(context))
            
            if poll(&pfd, 1, 1000) < 0 {
                return -1
            }
            
            if pfd.revents == 0 {
                continue
            }
            
            if smb2_service(context, Int32(pfd.revents)) < 0 {
                print(String(utf8String: smb2_get_error(context)) ?? "")
                return -1
            }
        }
        
        return 0
    }
    
    static let async_handler: @convention(c) (_ smb2: UnsafeMutablePointer<smb2_context>?, _ status: Int32, _ command_data: UnsafeMutableRawPointer?, _ cbdata: UnsafeMutableRawPointer?) -> Void = { smb2, status, _, cbdata in
        cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee.errNo = status
        cbdata?.bindMemory(to: CBData.self, capacity: 1).pointee.is_finished = true
    }
    
    func async_wait(execute handler: (_ cbPtr: UnsafeMutableRawPointer) -> Int32) throws -> Int32 {
        let cbPtr = CBData.initPointer()
        defer {
            cbPtr.deallocate()
        }
        
        let result = handler(cbPtr)
        
        if wait_for_reply(cbPtr) < 1 {
            throw POSIXError(.EIO)
        }
        
        let errNo = cbPtr.bindMemory(to: CBData.self, capacity: 1).pointee.errNo
        try POSIXError.throwIfError(errNo, default: .ECONNRESET)
        return result
    }
}
