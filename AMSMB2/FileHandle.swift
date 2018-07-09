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

final class SMB2FileHandle {
    
    struct SeekWhence: RawRepresentable {
        var rawValue: Int32
        
        static let set     = SeekWhence(rawValue: SEEK_SET)
        static let current = SeekWhence(rawValue: SEEK_CUR)
        static let end     = SeekWhence(rawValue: SEEK_END)
    }
    
    private var context: SMB2Context
    private let handle: smb2fh
    private var isOpen: Bool
    
    convenience init(forReadingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDONLY, on: context)
    }
    
    convenience init(forWritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY, on: context)
    }
    
    convenience init(forCreatingAndWritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT | O_TRUNC, on: context)
    }
    
    convenience init(forCreatingIfNotExistsAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT | O_EXCL, on: context)
    }
    
    convenience init(forUpdatingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDWR | O_APPEND, on: context)
    }
    
    private init(_ path: String, flags: Int32, on context: SMB2Context) throws {
        let (_, cmddata) = try context.async_wait(defaultError: .ENOENT) { (context, cbPtr) -> Int32 in
            smb2_open_async(context, path, flags, SMB2Context.async_handler, cbPtr)
        }
        
        guard let handle = OpaquePointer(cmddata) else {
            throw POSIXError(.ENOENT)
        }
        self.context = context
        self.handle = handle
        self.isOpen = true
    }
    
    deinit {
        if isOpen {
            _ = context.withThreadSafeContext { (context) in
                smb2_close(context, handle)
            }
        }
    }
    
    var fileId: smb2_file_id {
        return smb2_get_file_id(handle).pointee
    }
    
    func close() {
        _ = context.withThreadSafeContext { (context) in
            smb2_close(context, handle)
        }
        isOpen = false
    }
    
    func fstat() throws -> smb2_stat_64 {
        var st = smb2_stat_64()
        try context.async_wait(defaultError: .EBADF) { (context, cbPtr) -> Int32 in
            smb2_fstat_async(context, handle, &st, SMB2Context.async_handler, cbPtr)
        }
        return st
    }
    
    func ftruncate(toLength: UInt64) throws {
        try context.async_wait(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_ftruncate_async(context, handle, toLength, SMB2Context.async_handler, cbPtr)
        }
    }
    
    var maxReadSize: Int {
        return Int(smb2_get_max_read_size(context.context))
    }
    
    var optimizedReadSize: Int {
        return min(maxReadSize, 1048576)
    }
    
    @discardableResult
    func lseek(offset: Int64, whence: SeekWhence) throws -> Int64 {
        let result = smb2_lseek(context.context, handle, offset, whence.rawValue, nil)
        try POSIXError.throwIfError(Int32(exactly: result) ?? 0, description: context.error, default: .ESPIPE)
        return result
    }
    
    func read(length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let bufSize = length > 0 ? length : optimizedReadSize
        var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buffer.initialize(repeating: 0, count: bufSize)
        defer {
            buffer.deinitialize(count: bufSize)
            buffer.deallocate()
        }
        
        let (result, _) = try context.async_wait(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_read_async(context, handle, buffer, UInt32(bufSize), SMB2Context.async_handler, cbPtr)
        }
        return Data(bytes: buffer, count: Int(result))
    }
    
    func pread(offset: UInt64, length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let bufSize = length > 0 ? length : optimizedReadSize
        var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        buffer.initialize(repeating: 0, count: bufSize)
        defer {
            buffer.deinitialize(count: bufSize)
            buffer.deallocate()
        }
        
        let (result, _) = try context.async_wait(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_pread_async(context, handle, buffer, UInt32(bufSize), offset, SMB2Context.async_handler, cbPtr)
        }
        return Data(bytes: buffer, count: Int(result))
    }
    
    var maxWriteSize: Int {
        return Int(smb2_get_max_write_size(context.context))
    }
    
    var optimizedWriteSize: Int {
        // Some server may throw `POLLHUP` with size larger than this
        return min(maxWriteSize, 21000)
    }
    
    func write(data: Data) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        var result = 0
        var errorNo: Int32 = 0
        data.enumerateBytes { (bytes, dindex, stop) in
            guard let baseAddress = bytes.baseAddress else { return }
            let rc: Int32
            do {
                (rc, _) = try context.async_wait(defaultError: .EBUSY) { (context, cbPtr) -> Int32 in
                    smb2_write_async(context, handle, UnsafeMutablePointer(mutating: baseAddress), UInt32(bytes.count),
                                     SMB2Context.async_handler, cbPtr)
                }
                result += Int(rc)
                stop = false
            } catch {
                errorNo = -(error as! POSIXError).code.rawValue
                stop = true
            }
        }
        
        try POSIXError.throwIfError(errorNo, description: context.error, default: .EIO)
        return result
    }
    
    func pwrite(data: Data, offset: UInt64) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        var result = 0
        var errorNo: Int32 = 0
        data.enumerateBytes { (bytes, dindex, stop) in
            
            guard let baseAddress = bytes.baseAddress else { return }
            let rc: Int32
            do {
                (rc, _) = try context.async_wait(defaultError: .EBUSY) { (context, cbPtr) -> Int32 in
                    smb2_pwrite_async(context, handle, UnsafeMutablePointer(mutating: baseAddress), UInt32(bytes.count),
                                      offset + UInt64(dindex), SMB2Context.async_handler, cbPtr)
                }
                result += Int(rc)
                stop = false
            } catch {
                errorNo = -(error as! POSIXError).code.rawValue
                stop = true
            }
        }
        
        try POSIXError.throwIfError(errorNo, description: context.error, default: .EIO)
        return result
    }
    
    func fsync() throws {
        try context.async_wait(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_fsync_async(context, handle, SMB2Context.async_handler, cbPtr)
        }
    }
    
    func fcntl(command: IOCtl.Command, data: Data) throws -> Data {
        var data = data
        let count = UInt32(data.count)
        var req: smb2_ioctl_request
        if count > 0 {
            req = data.withUnsafeMutableBytes {
                smb2_ioctl_request(ctl_code: command.rawValue, file_id: fileId, input_count: count, input: $0, flags: UInt32(SMB2_0_IOCTL_IS_FSCTL))
            }
        } else {
            req = smb2_ioctl_request(ctl_code: command.rawValue, file_id: fileId, input_count: 0, input: nil, flags: UInt32(SMB2_0_IOCTL_IS_FSCTL))
        }
        
        let (_, response) = try context.async_wait_pdu(defaultError: .EBADRPC) { (context, cbdata) -> UnsafeMutablePointer<smb2_pdu>? in
            smb2_cmd_ioctl_async(context, &req, SMB2Context.async_handler, cbdata)
        }
        
        guard let reply = response?.bindMemory(to: smb2_ioctl_reply.self, capacity: 1) else {
            throw POSIXError(.EBADMSG, description: "No reply from ioctl command.")
        }
        defer {
            smb2_free_data(context.context, reply.pointee.output)
        }
        
        return Data(bytes: reply.pointee.output, count: Int(reply.pointee.output_count))
    }
    
    func fcntl(command: IOCtl.Command) throws -> Void {
        _=try fcntl(command: command, data: Data())
    }
    
    func fcntl<T: DataRepresentable>(command: IOCtl.Command, args: T) throws -> Void {
        _=try fcntl(command: command, data: args.data())
    }
    
    func fcntl<R: DataInitializable>(command: IOCtl.Command) throws -> R {
        let result = try fcntl(command: command, data: Data())
        return try R(data: result)
    }
    
    func fcntl<T: DataRepresentable, R: DataInitializable>(command: IOCtl.Command, args: T) throws -> R {
        let result = try fcntl(command: command, data: args.data())
        return try R(data: result)
    }
}
