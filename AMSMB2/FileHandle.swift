//
//  FileHandle.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2
import SMB2.Raw

typealias smb2fh = OpaquePointer

final class SMB2FileHandle {
    
    struct SeekWhence: RawRepresentable {
        var rawValue: Int32
        
        static let set     = SeekWhence(rawValue: SEEK_SET)
        static let current = SeekWhence(rawValue: SEEK_CUR)
        static let end     = SeekWhence(rawValue: SEEK_END)
    }
    
    private var context: SMB2Context
    private var _handle: smb2fh?
    
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
    
    convenience init(forPipe path: String, on context: SMB2Context) throws {
        // smb2_open() sets overwrite flag, which is incompatible with pipe in mac's smbx
        let (_, cmddata) = try context.async_await_pdu(defaultError: .ENOENT) { (context, cbPtr) -> UnsafeMutablePointer<smb2_pdu>? in
            return path.replacingOccurrences(of: "/", with: "\\").withCString { (path) in
                var req = smb2_create_request()
                req.requested_oplock_level = UInt8(SMB2_OPLOCK_LEVEL_NONE)
                req.impersonation_level = UInt32(SMB2_IMPERSONATION_IMPERSONATION)
                req.desired_access = UInt32(SMB2_FILE_READ_DATA | SMB2_FILE_READ_EA | SMB2_FILE_READ_ATTRIBUTES |
                    SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_EA | SMB2_FILE_WRITE_ATTRIBUTES)
                req.share_access = UInt32(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE)
                req.create_disposition = UInt32(SMB2_FILE_OPEN)
                req.create_options = UInt32(SMB2_FILE_NON_DIRECTORY_FILE)
                req.name = path
                return smb2_cmd_create_async(context, &req, SMB2Context.generic_handler, cbPtr)
            }
        }
        
        guard let reply = cmddata?.bindMemory(to: smb2_create_reply.self, capacity: 1) else {
            throw POSIXError(.EIO)
        }
        
        self.init(fileDescriptor: reply.pointee.file_id, on: context)
    }
    
    init(fileDescriptor: smb2_file_id, on context: SMB2Context) {
        self.context = context
        var fileDescriptor = fileDescriptor
        self._handle = smb2_fh_from_file_id(context.context, &fileDescriptor)
    }
    
    private init(_ path: String, flags: Int32, on context: SMB2Context) throws {
        let (_, cmddata) = try context.async_await(defaultError: .ENOENT) { (context, cbPtr) -> Int32 in
            smb2_open_async(context, path, flags, SMB2Context.generic_handler, cbPtr)
        }
        
        guard let handle = smb2fh(cmddata) else {
            throw POSIXError(.ENOENT)
        }
        self.context = context
        self._handle = handle
    }
    
    deinit {
        guard let handle = _handle else { return }
        _ = try? context.withThreadSafeContext { (context) in
            smb2_close(context, handle)
        }
    }
    
    var fileId: smb2_file_id {
        guard let id = smb2_get_file_id(_handle) else {
            return compound_file_id
        }
        return id.pointee
    }
    
    func close() {
        guard let handle = _handle else { return }
        _handle = nil
        _ = try? context.withThreadSafeContext { (context) in
            smb2_close(context, handle)
        }
    }
    
    func fstat() throws -> smb2_stat_64 {
        let handle = try self.handle()
        var st = smb2_stat_64()
        try context.async_await(defaultError: .EBADF) { (context, cbPtr) -> Int32 in
            smb2_fstat_async(context, handle, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func ftruncate(toLength: UInt64) throws {
        let handle = try self.handle()
        try context.async_await(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_ftruncate_async(context, handle, toLength, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    var maxReadSize: Int {
        return Int(smb2_get_max_read_size(context.context))
    }
    
    /// This value allows softer streaming
    var optimizedReadSize: Int {
        return min(maxReadSize, 1048576)
    }
    
    @discardableResult
    func lseek(offset: Int64, whence: SeekWhence) throws -> Int64 {
        let handle = try self.handle()
        let result = smb2_lseek(context.context, handle, offset, whence.rawValue, nil)
        if result < 0 {
            try POSIXError.throwIfError(Int32(result), description: context.error, default: .ESPIPE)
        }
        return result
    }
    
    func read(length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let handle = try self.handle()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let (result, _) = try context.async_await(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_read_async(context, handle, &buffer, UInt32(buffer.count), SMB2Context.generic_handler, cbPtr)
        }
        return Data(buffer.prefix(Int(result)))
    }
    
    func pread(offset: UInt64, length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let handle = try self.handle()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let (result, _) = try context.async_await(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_pread_async(context, handle, &buffer, UInt32(buffer.count), offset, SMB2Context.generic_handler, cbPtr)
        }
        return Data(buffer.prefix(Int(result)))
    }
    
    var maxWriteSize: Int {
        return Int(smb2_get_max_write_size(context.context))
    }
    
    var optimizedWriteSize: Int {
        return min(maxWriteSize, 1048576)
    }
    
    func write(data: Data) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        let handle = try self.handle()
        var buffer = Array(data)
        let (result, _) = try context.async_await(defaultError: .EBUSY) { (context, cbPtr) -> Int32 in
            smb2_write_async(context, handle, &buffer, UInt32(buffer.count), SMB2Context.generic_handler, cbPtr)
        }
        
        return Int(result)
    }
    
    func pwrite(data: Data, offset: UInt64) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        let handle = try self.handle()
        var buffer = Array(data)
        let (result, _) = try context.async_await(defaultError: .EBUSY) { (context, cbPtr) -> Int32 in
            smb2_pwrite_async(context, handle, &buffer, UInt32(buffer.count), offset, SMB2Context.generic_handler, cbPtr)
        }
        
        return Int(result)
    }
    
    func fsync() throws {
        let handle = try self.handle()
        try context.async_await(defaultError: .EIO) { (context, cbPtr) -> Int32 in
            smb2_fsync_async(context, handle, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    @discardableResult
    func fcntl(command: IOCtl.Command, data: Data, needsReply: Bool = true) throws -> Data {
        var buffer = [UInt8](data)
        var req = smb2_ioctl_request(ctl_code: command.rawValue, file_id: fileId, input_count: UInt32(buffer.count),
                                 input: &buffer, flags: UInt32(SMB2_0_IOCTL_IS_FSCTL))
        
        let (_, response) = try context.async_await_pdu(defaultError: .EBADRPC) {
            (context, cbPtr) -> UnsafeMutablePointer<smb2_pdu>? in
            smb2_cmd_ioctl_async(context, &req, SMB2Context.generic_handler, cbPtr)
        }
        
        guard let reply = response?.bindMemory(to: smb2_ioctl_reply.self, capacity: 1).pointee else {
            throw POSIXError(.EBADMSG, description: "Bad reply from ioctl command.")
        }
        
        guard reply.output_count > 0, let output = reply.output else {
            return Data()
        }
        
        if needsReply {
            if reply.output_count > command.maxResponseSize {
                throw POSIXError(.EBADMSG, description: "Bad reply from ioctl command.")
            }
            defer {
                smb2_free_data(context.context, output)
            }
            return Data(bytes: output, count: Int(reply.output_count))
        } else {
            if reply.output_count <= command.maxResponseSize {
                smb2_free_data(context.context, output)
            }
            return Data()
        }
    }
    
    func fcntl(command: IOCtl.Command) throws -> Void {
        try fcntl(command: command, data: Data(), needsReply: false)
    }
    
    func fcntl<T: DataProtocol>(command: IOCtl.Command, args: T) throws -> Void where T.Regions == CollectionOfOne<Data> {
        try fcntl(command: command, data: args.regions[0], needsReply: false)
    }
    
    func fcntl<R: DataInitializable>(command: IOCtl.Command) throws -> R {
        let result = try fcntl(command: command, data: Data())
        return try R(data: result)
    }
    
    func fcntl<T: DataProtocol, R: DataInitializable>(command: IOCtl.Command, args: T) throws -> R where T.Regions == CollectionOfOne<Data> {
        let result = try fcntl(command: command, data: args.regions[0])
        return try R(data: result)
    }
}

fileprivate extension SMB2FileHandle {
    func handle() throws -> smb2fh {
        guard let handle = _handle else {
            throw POSIXError(.EBADF, description: "SMB2 file is already closed.")
        }
        return handle
    }
}
