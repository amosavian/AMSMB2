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
    private var handle: smb2fh?
    
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
        try self.init(path, flags: O_RDWR | O_CREAT | O_EXCL, on: context)
    }
    
    convenience init(forUpdatingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDWR | O_APPEND, on: context)
    }
    
    convenience init(path: String,
                     opLock: Int32 = SMB2_OPLOCK_LEVEL_NONE,
                     impersonation: Int32 = SMB2_IMPERSONATION_IMPERSONATION,
                     desiredAccess: Int32 = SMB2_FILE_READ_DATA | SMB2_FILE_WRITE_DATA | SMB2_FILE_APPEND_DATA | SMB2_FILE_READ_EA |
        SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_WRITE_EA | SMB2_FILE_WRITE_ATTRIBUTES | SMB2_READ_CONTROL | SMB2_SYNCHRONIZE,
                     fileAttributes: Int32 = 0,
                     shareAccess: Int32 = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE,
                     createDisposition: Int32 = SMB2_FILE_OPEN,
                     createOptions: Int32 = 0, on context: SMB2Context) throws {
        let (_, file_id) = try context.async_await_pdu(dataHandler: Parser.toFileId) { (context, cbPtr) -> UnsafeMutablePointer<smb2_pdu>? in
            return path.replacingOccurrences(of: "/", with: "\\").withCString { (path) in
                var req = smb2_create_request()
                req.requested_oplock_level = UInt8(opLock)
                req.impersonation_level = UInt32(impersonation)
                req.desired_access = UInt32(desiredAccess)
                req.file_attributes = UInt32(fileAttributes)
                req.share_access = UInt32(shareAccess)
                req.create_disposition = UInt32(createDisposition)
                req.create_options = UInt32(createOptions)
                req.name = path
                return smb2_cmd_create_async(context, &req, SMB2Context.generic_handler, cbPtr)
            }
        }
        
        try self.init(fileDescriptor: file_id, on: context)
    }
    
    init(fileDescriptor: smb2_file_id, on context: SMB2Context) throws {
        self.context = context
        var fileDescriptor = fileDescriptor
        self.handle = try context.withThreadSafeContext { context in
            smb2_fh_from_file_id(context, &fileDescriptor)
        }
    }
    
    private init(_ path: String, flags: Int32, on context: SMB2Context) throws {
        let (_, handle) = try context.async_await(dataHandler: Parser.toOpaquePointer) { (context, cbPtr) -> Int32 in
            smb2_open_async(context, path, flags, SMB2Context.generic_handler, cbPtr)
        }
        self.context = context
        self.handle = handle
    }
    
    deinit {
        do {
            let handle = try self.handle.unwrap()
            try context.async_await { (context, cbPtr) -> Int32 in
                smb2_close_async(context, handle, SMB2Context.generic_handler, cbPtr)
            }
        } catch { }
    }
    
    var fileId: smb2_file_id {
        return (try? smb2_get_file_id(handle.unwrap()).unwrap().pointee) ?? compound_file_id
    }
    
    func close() {
        guard let handle = handle else { return }
        self.handle = nil
        _ = try? context.withThreadSafeContext { (context) in
            smb2_close(context, handle)
        }
    }
    
    func fstat() throws -> smb2_stat_64 {
        let handle = try self.handle.unwrap()
        var st = smb2_stat_64()
        try context.async_await { (context, cbPtr) -> Int32 in
            smb2_fstat_async(context, handle, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func ftruncate(toLength: UInt64) throws {
        let handle = try self.handle.unwrap()
        try context.async_await { (context, cbPtr) -> Int32 in
            smb2_ftruncate_async(context, handle, toLength, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    var maxReadSize: Int {
        return (try? Int(context.withThreadSafeContext(smb2_get_max_read_size))) ?? -1
    }
    
    /// This value allows softer streaming
    var optimizedReadSize: Int {
        return min(maxReadSize, 1048576)
    }
    
    @discardableResult
    func lseek(offset: Int64, whence: SeekWhence) throws -> Int64 {
        let handle = try self.handle.unwrap()
        let result = smb2_lseek(context.context, handle, offset, whence.rawValue, nil)
        if result < 0 {
            try POSIXError.throwIfError(Int32(result), description: context.error)
        }
        return result
    }
    
    func read(length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let handle = try self.handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let result = try context.async_await { (context, cbPtr) -> Int32 in
            smb2_read_async(context, handle, &buffer, UInt32(buffer.count), SMB2Context.generic_handler, cbPtr)
        }
        return Data(buffer.prefix(Int(result)))
    }
    
    func pread(offset: UInt64, length: Int = 0) throws -> Data {
        precondition(length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2.")
        
        let handle = try self.handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let result = try context.async_await { (context, cbPtr) -> Int32 in
            smb2_pread_async(context, handle, &buffer, UInt32(buffer.count), offset, SMB2Context.generic_handler, cbPtr)
        }
        return Data(buffer.prefix(Int(result)))
    }
    
    var maxWriteSize: Int {
        return (try? Int(context.withThreadSafeContext(smb2_get_max_write_size))) ?? -1
    }
    
    var optimizedWriteSize: Int {
        return min(maxWriteSize, 1048576)
    }
    
    func write<DataType: DataProtocol>(data: DataType) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        let handle = try self.handle.unwrap()
        var buffer = Array(data)
        let result = try context.async_await { (context, cbPtr) -> Int32 in
            smb2_write_async(context, handle, &buffer, UInt32(buffer.count), SMB2Context.generic_handler, cbPtr)
        }
        
        return Int(result)
    }
    
    func pwrite<DataType: DataProtocol>(data: DataType, offset: UInt64) throws -> Int {
        precondition(data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2.")
        
        let handle = try self.handle.unwrap()
        var buffer = Array(data)
        let result = try context.async_await { (context, cbPtr) -> Int32 in
            smb2_pwrite_async(context, handle, &buffer, UInt32(buffer.count), offset, SMB2Context.generic_handler, cbPtr)
        }
        
        return Int(result)
    }
    
    func fsync() throws {
        let handle = try self.handle.unwrap()
        try context.async_await { (context, cbPtr) -> Int32 in
            smb2_fsync_async(context, handle, SMB2Context.generic_handler, cbPtr)
        }
    }
    
    @discardableResult
    func fcntl<DataType: DataProtocol, R: DataInitializable>(command: IOCtl.Command, data: DataType, needsReply: Bool = true) throws -> R {
        var inputBUffer = [UInt8](data)
        var req = smb2_ioctl_request(ctl_code: command.rawValue, file_id: fileId, input_count: UInt32(inputBUffer.count),
                                     input: &inputBUffer, flags: UInt32(SMB2_0_IOCTL_IS_FSCTL))
        let outputHandler = Parser.ioctlOutputConverter(as: R.self)
        return try context.async_await_pdu(dataHandler: outputHandler) {
            (context, cbPtr) -> UnsafeMutablePointer<smb2_pdu>? in
            smb2_cmd_ioctl_async(context, &req, SMB2Context.generic_handler, cbPtr)
        }.data
    }
    
    func fcntl(command: IOCtl.Command) throws -> Void {
        let _: Data = try fcntl(command: command, data: [], needsReply: false)
    }
    
    func fcntl<DataType: DataProtocol>(command: IOCtl.Command, args: DataType) throws -> Void {
        let _: Data = try fcntl(command: command, data: args, needsReply: false)
    }
    
    func fcntl<R: DataInitializable>(command: IOCtl.Command) throws -> R {
        return try fcntl(command: command, data: [])
    }
    
    func fcntl<DataType: DataProtocol, R: DataInitializable>(command: IOCtl.Command, args: DataType) throws -> R {
        return try fcntl(command: command, data: args)
    }
}
