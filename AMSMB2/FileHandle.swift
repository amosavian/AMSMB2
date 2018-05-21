//
//  FileHandle.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2

typealias smb2fh = OpaquePointer

class SMB2FileHanle {
    fileprivate var context: SMB2Context
    fileprivate let handle: smb2fh
    fileprivate var isOpen: Bool
    
    convenience init(forReadingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDONLY, on: context)
    }
    
    convenience init(forWritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY, on: context)
    }
    
    convenience init(forCreatingAndWritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT | O_TRUNC, on: context)
    }
    
    convenience init(forUpdatingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDWR, on: context)
    }
    
    private init(_ path: String, flags: Int32, on context: SMB2Context) throws {
        guard let handle = smb2_open(context.context, path, flags) else {
            throw POSIXError(.EBADF)
        }
        self.context = context
        self.handle = handle
        self.isOpen = true
    }
    
    deinit {
        if isOpen {
            smb2_close(context.context, handle)
        }
    }
    
    func close() {
        smb2_close(context.context, handle)
        isOpen = false
    }
    
    func fstat() throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        let result = smb2_fstat(context.context, handle, &st)
        try POSIXError.throwIfError(result, default: .EBADF)
        return st
    }
    
    func ftruncate(toLength: UInt64) {
        smb2_ftruncate(context.context, handle, toLength)
    }
    
    var maxReadSize: Int {
        return Int(smb2_get_max_read_size(context.context))
    }
    
    var optimizedReadSize: Int {
        return min(maxReadSize, 65535)
    }
    
    func lseek(offset: Int64) throws -> Int64 {
        let result = smb2_lseek(context.context, handle, offset, SEEK_SET, nil)
        if result < 0 {
            let error: Error? = POSIXErrorCode(rawValue: Int32(abs(result))).map { POSIXError($0) }
            throw error ?? POSIXError(POSIXError.ESPIPE)
        }
        try POSIXError.throwIfError(Int32(exactly: result) ?? 0, default: .ESPIPE)
        return result
    }
    
    func read() throws -> Data {
        let bufSize = optimizedReadSize
        var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buffer.initialize(repeating: 0, count: bufSize)
        defer {
            buffer.deinitialize(count: bufSize)
            buffer.deallocate()
        }
        
        let result = smb2_read(context.context, handle, buffer, UInt32(bufSize))
        try POSIXError.throwIfError(result, default: .EIO)
        return Data(bytes: buffer, count: Int(result))
    }
    
    func pread(offset: UInt64) throws -> Data {
        let bufSize = optimizedReadSize
        var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buffer.initialize(repeating: 0, count: bufSize)
        defer {
            buffer.deinitialize(count: bufSize)
            buffer.deallocate()
        }
        
        let result = smb2_pread(context.context, handle, buffer, UInt32(bufSize), offset)
        try POSIXError.throwIfError(result, default: .EIO)
        return Data(bytes: buffer, count: Int(result))
    }
    
    var maxWriteSize: Int {
        return Int(smb2_get_max_write_size(context.context))
    }
    
    var optimizedWriteSize: Int {
        return min(maxWriteSize, 65535)
    }
    
    func write(data: Data) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        var result = 0
        var errorNo: Int32 = 0
        data.enumerateBytes { (bytes, dindex, stop) in
            guard let baseAddress = bytes.baseAddress else { return }
            let rc = smb2_write(context.context, handle, UnsafeMutablePointer(mutating: baseAddress), UInt32(bytes.count))
            if rc > 0 {
                result += Int(rc)
                stop = false
            } else {
                errorNo = rc
                stop = true
            }
        }
        
        try POSIXError.throwIfError(errorNo, default: .EIO)
        return result
    }
    
    func write_async(data: Data) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        var array = [UInt8](data)
        let result = try array.withUnsafeMutableBufferPointer { (bytes) -> Int32 in
            guard let baseAddress = bytes.baseAddress else { return 0 }
            return try context.async_wait { (cbPtr) -> Int32 in
                smb2_write_async(context.context, handle, baseAddress, UInt32(bytes.count), SMB2Context.async_handler, cbPtr)
            }
        }
        
        try POSIXError.throwIfError(result, default: .EIO)
        return Int(result)
    }
    
    func pwrite(data: Data, offset: UInt64) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        var result = 0
        var errorNo: Int32 = 0
        data.enumerateBytes { (bytes, dindex, stop) in
            guard let baseAddress = bytes.baseAddress else { return }
            let rc = smb2_pwrite(context.context, handle, UnsafeMutablePointer(mutating: baseAddress), UInt32(bytes.count), offset + UInt64(dindex))
            if rc > 0 {
                result += Int(rc)
                stop = false
            } else {
                errorNo = rc
                stop = true
            }
        }
        
        try POSIXError.throwIfError(errorNo, default: .EIO)
        return result
    }
    
    func fsync() throws {
        let result = smb2_fsync(context.context, handle)
        try POSIXError.throwIfError(result, default: .EIO)
    }
}
