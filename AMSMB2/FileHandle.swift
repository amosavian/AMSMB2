//
//  FileHandle.swift
//  AMSMB2
//
//  Created by Amir Abbas on 12/15/23.
//  Copyright © 2023 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

typealias smb2fh = OpaquePointer

final class SMB2FileHandle {
    struct SeekWhence: RawRepresentable {
        var rawValue: Int32

        static let set = SeekWhence(rawValue: SEEK_SET)
        static let current = SeekWhence(rawValue: SEEK_CUR)
        static let end = SeekWhence(rawValue: SEEK_END)
    }

    private var context: SMB2Context
    private var handle: smb2fh?

    convenience init(forReadingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDONLY, on: context)
    }

    convenience init(forWritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY, on: context)
    }

    convenience init(forUpdatingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDWR | O_APPEND, on: context)
    }

    convenience init(forOverwritingAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT | O_TRUNC, on: context)
    }

    convenience init(forOutputAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT, on: context)
    }
    
    convenience init(forCreatingIfNotExistsAtPath path: String, on context: SMB2Context) throws {
        try self.init(path, flags: O_RDWR | O_CREAT | O_EXCL, on: context)
    }

    static func using(
        path: String,
        opLock: Int32 = SMB2_OPLOCK_LEVEL_NONE,
        impersonation: Int32 = SMB2_IMPERSONATION_IMPERSONATION,
        desiredAccess: Int32 = SMB2_FILE_READ_DATA | SMB2_FILE_WRITE_DATA | SMB2_FILE_APPEND_DATA
            | SMB2_FILE_READ_EA | SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_WRITE_EA
            | SMB2_FILE_WRITE_ATTRIBUTES | SMB2_READ_CONTROL | SMB2_SYNCHRONIZE,
        fileAttributes: Int32 = 0,
        shareAccess: Int32 = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE,
        createDisposition: Int32 = SMB2_FILE_OPEN,
        createOptions: Int32 = 0, on context: SMB2Context
    ) throws -> SMB2FileHandle {
        let (_, result) = try context.async_await_pdu(dataHandler: SMB2FileHandle.init) {
            context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
            path.replacingOccurrences(of: "/", with: "\\").withCString { path in
                var req = smb2_create_request()
                req.requested_oplock_level = .init(bitPattern: .init(opLock))
                req.impersonation_level = .init(bitPattern: impersonation)
                req.desired_access = .init(bitPattern: desiredAccess)
                req.file_attributes = .init(bitPattern: fileAttributes)
                req.share_access = .init(bitPattern: shareAccess)
                req.create_disposition = .init(bitPattern: createDisposition)
                req.create_options = .init(bitPattern: createOptions)
                req.name = path
                return smb2_cmd_create_async(context, &req, SMB2Context.generic_handler, cbPtr)
            }
        }

        return result
    }
    
    static func open(path: String, flags: Int32, on context: SMB2Context) throws -> SMB2FileHandle {
        let desiredAccess: Int32
        let shareAccess: Int32
        let createDisposition: Int32
        var createOptions: Int32 = 0
        
        switch flags & O_ACCMODE {
        case O_RDWR:
            desiredAccess = .init(bitPattern: SMB2_GENERIC_READ) | SMB2_GENERIC_WRITE | SMB2_DELETE
            shareAccess = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE
        case O_WRONLY:
            desiredAccess = SMB2_GENERIC_WRITE | SMB2_DELETE
            shareAccess = SMB2_FILE_SHARE_WRITE
        default:
            desiredAccess = .init(bitPattern: SMB2_GENERIC_READ)
            shareAccess = SMB2_FILE_SHARE_READ
        }
        
        if (flags & O_CREAT) != 0 {
            if (flags & O_EXCL) != 0 {
                createDisposition = SMB2_FILE_CREATE
            } else if (flags & O_TRUNC) != 0 {
                createDisposition = SMB2_FILE_OVERWRITE_IF
            } else {
                createDisposition = SMB2_FILE_OPEN_IF
            }
        } else {
            if (flags & O_TRUNC) != 0 {
                createDisposition = SMB2_FILE_OVERWRITE
            } else {
                createDisposition = SMB2_FILE_OPEN
            }
        }
        
        if (flags & O_DIRECTORY) != 0 {
            createOptions |= SMB2_FILE_DIRECTORY_FILE
        }
        if (flags & O_SYMLINK) != 0 {
            createOptions |= SMB2_FILE_OPEN_REPARSE_POINT
        }
        
        return try SMB2FileHandle.using(
            path: path,
            desiredAccess: desiredAccess,
            shareAccess: shareAccess,
            createDisposition: createDisposition,
            createOptions: createOptions,
            on: context
        )
    }

    init(fileDescriptor: smb2_file_id, on context: SMB2Context) throws {
        self.context = context
        var fileDescriptor = fileDescriptor
        self.handle = smb2_fh_from_file_id(context.unsafe, &fileDescriptor)
    }

    private init(_ path: String, flags: Int32, on context: SMB2Context) throws {
        let (_, handle) = try context.async_await(dataHandler: OpaquePointer.init) {
            context, cbPtr -> Int32 in
            smb2_open_async(context, path.canonical, flags, SMB2Context.generic_handler, cbPtr)
        }
        self.context = context
        self.handle = handle
    }

    deinit {
        do {
            let handle = try self.handle.unwrap()
            try context.async_await { context, cbPtr -> Int32 in
                smb2_close_async(context, handle, SMB2Context.generic_handler, cbPtr)
            }
        } catch {}
    }

    var fileId: UUID {
        .init(uuid: (try? smb2_get_file_id(handle.unwrap()).unwrap().pointee) ?? compound_file_id)
    }

    func close() {
        guard let handle = handle else { return }
        self.handle = nil
        _ = try? context.withThreadSafeContext { context in
            smb2_close(context, handle)
        }
    }

    func fstat() throws -> smb2_stat_64 {
        let handle = try handle.unwrap()
        var st = smb2_stat_64()
        try context.async_await { context, cbPtr -> Int32 in
            smb2_fstat_async(context, handle, &st, SMB2Context.generic_handler, cbPtr)
        }
        return st
    }
    
    func set(stat: smb2_stat_64, attributes: SMB2FileAttributes) throws {
        let handle = try handle.unwrap()
        try context.async_await_pdu(dataHandler: EmptyReply.init) {
            context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
            var bfi = smb2_file_basic_info(
                creation_time: smb2_timeval(
                    tv_sec: .init(stat.smb2_btime),
                    tv_usec: .init(stat.smb2_btime_nsec / 1000)
                ),
                last_access_time: smb2_timeval(
                    tv_sec: .init(stat.smb2_atime),
                    tv_usec: .init(stat.smb2_atime_nsec / 1000)
                ),
                last_write_time: smb2_timeval(
                    tv_sec: .init(stat.smb2_mtime),
                    tv_usec: .init(stat.smb2_mtime_nsec / 1000)
                ),
                change_time: smb2_timeval(
                    tv_sec: .init(stat.smb2_ctime),
                    tv_usec: .init(stat.smb2_ctime_nsec / 1000)
                ),
                file_attributes: attributes.rawValue
            )
            
            var req = smb2_set_info_request()
            req.file_id = smb2_get_file_id(handle).pointee
            req.info_type = .init(SMB2_0_INFO_FILE)
            req.file_info_class = .init(SMB2_FILE_BASIC_INFORMATION)
            return withUnsafeMutablePointer(to: &bfi) { bfi in
                req.input_data = .init(bfi)
                return smb2_cmd_set_info_async(context, &req, SMB2Context.generic_handler, cbPtr)
            }
        }
    }

    func ftruncate(toLength: UInt64) throws {
        let handle = try handle.unwrap()
        try context.async_await { context, cbPtr -> Int32 in
            smb2_ftruncate_async(context, handle, toLength, SMB2Context.generic_handler, cbPtr)
        }
    }

    var maxReadSize: Int {
        (try? Int(context.withThreadSafeContext(smb2_get_max_read_size))) ?? -1
    }

    /// This value allows softer streaming
    var optimizedReadSize: Int {
        min(maxReadSize, 1_048_576)
    }

    @discardableResult
    func lseek(offset: Int64, whence: SeekWhence) throws -> Int64 {
        let handle = try handle.unwrap()
        let result = smb2_lseek(context.unsafe, handle, offset, whence.rawValue, nil)
        try POSIXError.throwIfError(result, description: context.error)
        return result
    }

    func read(length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let result = try context.async_await { context, cbPtr -> Int32 in
            smb2_read_async(
                context, handle, &buffer, .init(buffer.count), SMB2Context.generic_handler, cbPtr
            )
        }
        return Data(buffer.prefix(Int(result)))
    }

    func pread(offset: UInt64, length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = [UInt8](repeating: 0, count: count)
        let result = try context.async_await { context, cbPtr -> Int32 in
            smb2_pread_async(
                context, handle, &buffer, .init(buffer.count), offset, SMB2Context.generic_handler,
                cbPtr
            )
        }
        return Data(buffer.prefix(Int(result)))
    }

    var maxWriteSize: Int {
        (try? Int(context.withThreadSafeContext(smb2_get_max_write_size))) ?? -1
    }

    var optimizedWriteSize: Int {
        min(maxWriteSize, 1_048_576)
    }

    func write<DataType: DataProtocol>(data: DataType) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        var buffer = Array(data)
        let result = try context.async_await { context, cbPtr -> Int32 in
            smb2_write_async(
                context, handle, &buffer, .init(buffer.count), SMB2Context.generic_handler, cbPtr
            )
        }

        return Int(result)
    }

    func pwrite<DataType: DataProtocol>(data: DataType, offset: UInt64) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        var buffer = Array(data)
        let result = try context.async_await { context, cbPtr -> Int32 in
            smb2_pwrite_async(
                context, handle, &buffer, .init(buffer.count), offset, SMB2Context.generic_handler,
                cbPtr
            )
        }

        return Int(result)
    }

    func fsync() throws {
        let handle = try handle.unwrap()
        try context.async_await { context, cbPtr -> Int32 in
            smb2_fsync_async(context, handle, SMB2Context.generic_handler, cbPtr)
        }
    }

    @discardableResult
    func fcntl<DataType: DataProtocol, R: IOCtlReply>(
        command: IOCtl.Command, args: DataType, needsReply _: Bool = true
    ) throws -> R {
        var inputBuffer = [UInt8](args)
        return try inputBuffer.withUnsafeMutableBytes { buf in
            var req = smb2_ioctl_request(
                ctl_code: command.rawValue, file_id: fileId.uuid, input_count: .init(buf.count),
                input: buf.baseAddress, flags: .init(SMB2_0_IOCTL_IS_FSCTL)
            )
            return try context.async_await_pdu(dataHandler: R.init) {
                context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
                smb2_cmd_ioctl_async(context, &req, SMB2Context.generic_handler, cbPtr)
            }.data
        }
    }

    func fcntl(command: IOCtl.Command) throws {
        let _: AnyIOCtlReply = try fcntl(command: command, args: Data(), needsReply: false)
    }

    func fcntl<DataType: DataProtocol>(command: IOCtl.Command, args: DataType) throws {
        let _: AnyIOCtlReply = try fcntl(command: command, args: args, needsReply: false)
    }

    func fcntl<R: IOCtlReply>(command: IOCtl.Command) throws -> R {
        try fcntl(command: command, args: [])
    }
}

struct SMB2FileAttributes: OptionSet, Sendable {
    var rawValue: UInt32
    
    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    static let readonly = Self(rawValue: SMB2_FILE_ATTRIBUTE_READONLY)
    static let hidden = Self(rawValue: SMB2_FILE_ATTRIBUTE_HIDDEN)
    static let system = Self(rawValue: SMB2_FILE_ATTRIBUTE_SYSTEM)
    static let directory = Self(rawValue: SMB2_FILE_ATTRIBUTE_DIRECTORY)
    static let archive = Self(rawValue: SMB2_FILE_ATTRIBUTE_ARCHIVE)
    static let normal = Self(rawValue: SMB2_FILE_ATTRIBUTE_NORMAL)
    static let temporary = Self(rawValue: SMB2_FILE_ATTRIBUTE_TEMPORARY)
    static let sparseFile = Self(rawValue: SMB2_FILE_ATTRIBUTE_SPARSE_FILE)
    static let reparsePoint = Self(rawValue: SMB2_FILE_ATTRIBUTE_REPARSE_POINT)
    static let compressed = Self(rawValue: SMB2_FILE_ATTRIBUTE_COMPRESSED)
    static let offline = Self(rawValue: SMB2_FILE_ATTRIBUTE_OFFLINE)
    static let notContentIndexed = Self(rawValue: SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    static let encrypted = Self(rawValue: SMB2_FILE_ATTRIBUTE_ENCRYPTED)
    static let integrityStream = Self(rawValue: SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM)
    static let noScrubData = Self(rawValue: SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA)
}
