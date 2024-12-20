//
//  FileHandle.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2
import SMB2.Raw

typealias smb2fh = OpaquePointer

#if os(Linux) || os(Android) || os(OpenBSD)
let O_SYMLINK: Int32 = O_NOFOLLOW
#endif

final class SMB2FileHandle: @unchecked Sendable {
    private var client: SMB2Client
    private var handle: smb2fh?

    convenience init(forReadingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_RDONLY, on: client)
    }

    convenience init(forWritingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_WRONLY, on: client)
    }

    convenience init(forUpdatingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_RDWR | O_APPEND, on: client)
    }

    convenience init(forOverwritingAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT | O_TRUNC, on: client)
    }

    convenience init(forOutputAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_WRONLY | O_CREAT, on: client)
    }
    
    convenience init(forCreatingIfNotExistsAtPath path: String, on client: SMB2Client) throws {
        try self.init(path, flags: O_RDWR | O_CREAT | O_EXCL, on: client)
    }

    convenience init(
        path: String,
        opLock: OpLock = .none,
        impersonation: ImpersonationLevel = .impersonation,
        desiredAccess: Access = [.read, .write, .synchronize],
        fileAttributes: Attributes = [],
        shareAccess: ShareAccess = [.read, .write],
        createDisposition: CreateDisposition,
        createOptions: CreateOptions = [], on client: SMB2Client
    ) throws {
        var leaseData = opLock.leaseContext.map { Data($0.regions.joined()) } ?? .init()
        
        let (_, result) = try withExtendedLifetime(leaseData) {
            try path.replacingOccurrences(of: "/", with: "\\").withCString { path in
                try client.async_await_pdu(dataHandler: SMB2FileID.init) {
                    context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
                    var req = smb2_create_request()
                    req.requested_oplock_level = opLock.lockLevel
                    req.impersonation_level = impersonation.rawValue
                    req.desired_access = desiredAccess.rawValue
                    req.file_attributes = fileAttributes.rawValue
                    req.share_access = shareAccess.rawValue
                    req.create_disposition = createDisposition.rawValue
                    req.create_options = createOptions.rawValue
                    req.name = path
                    leaseData.withUnsafeMutableBytes {
                        req.create_context = $0.count > 0 ? $0.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil
                        req.create_context_length = UInt32($0.count)
                    }
                    return smb2_cmd_create_async(context, &req, SMB2Client.generic_handler, cbPtr)
                }
            }
        }
        try self.init(fileDescriptor: result.rawValue, on: client)
    }
    
    convenience init(path: String, flags: Int32, lock: OpLock = .none, on client: SMB2Client) throws {
        try self.init(
            path: path,
            opLock: lock,
            desiredAccess: .init(flags: flags),
            shareAccess: .init(flags: flags),
            createDisposition: .init(flags: flags),
            createOptions: .init(flags: flags),
            on: client
        )
    }

    init(fileDescriptor: smb2_file_id, on client: SMB2Client) throws {
        self.client = client
        var fileDescriptor = fileDescriptor
        self.handle = smb2_fh_from_file_id(client.context, &fileDescriptor)
    }

    // This initializer does not support O_DIRECTORY and O_SYMLINK.
    private init(_ path: String, flags: Int32, lock: OpLock = .none, on client: SMB2Client) throws {
        let (_, handle) = try client.async_await(dataHandler: OpaquePointer.init) {
            context, cbPtr -> Int32 in
            var leaseKey = lock.leaseContext.map { Data(value: $0.key) } ?? Data()
            return leaseKey.withUnsafeMutableBytes {
                smb2_open_async_with_oplock_or_lease(
                    context, path.canonical, flags,
                    lock.lockLevel, lock.leaseState.rawValue,
                    !$0.isEmpty ? $0.baseAddress : nil,
                    SMB2Client.generic_handler, cbPtr
                )
            }
        }
        self.client = client
        self.handle = handle
    }

    deinit {
        do {
            let handle = try self.handle.unwrap()
            try client.async_await { context, cbPtr -> Int32 in
                smb2_close_async(context, handle, SMB2Client.generic_handler, cbPtr)
            }
        } catch {}
    }

    var fileId: UUID {
        .init(uuid: (try? smb2_get_file_id(handle.unwrap()).unwrap().pointee) ?? compound_file_id)
    }

    func close() {
        guard let handle = handle else { return }
        self.handle = nil
        _ = try? client.withThreadSafeContext { context in
            smb2_close(context, handle)
        }
    }

    func fstat() throws -> smb2_stat_64 {
        let handle = try handle.unwrap()
        var st = smb2_stat_64()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_fstat_async(context, handle, &st, SMB2Client.generic_handler, cbPtr)
        }
        return st
    }
    
    func set(stat: smb2_stat_64, attributes: Attributes) throws {
        try client.async_await_pdu(dataHandler: EmptyReply.init) {
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
            req.file_id = fileId.uuid
            req.info_type = .init(SMB2_0_INFO_FILE)
            req.file_info_class = .init(SMB2_FILE_BASIC_INFORMATION)
            return withUnsafeMutablePointer(to: &bfi) { bfi in
                req.input_data = .init(bfi)
                return smb2_cmd_set_info_async(context, &req, SMB2Client.generic_handler, cbPtr)
            }
        }
    }

    func ftruncate(toLength: UInt64) throws {
        let handle = try handle.unwrap()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_ftruncate_async(context, handle, toLength, SMB2Client.generic_handler, cbPtr)
        }
    }

    var maxReadSize: Int {
        (try? Int(client.withThreadSafeContext(smb2_get_max_read_size))) ?? -1
    }

    /// This value allows softer streaming
    var optimizedReadSize: Int {
        maxReadSize
    }

    @discardableResult
    func lseek(offset: Int64, whence: SeekWhence) throws -> Int64 {
        let handle = try handle.unwrap()
        let result = smb2_lseek(client.context, handle, offset, whence.rawValue, nil)
        try POSIXError.throwIfError(result, description: client.error)
        return result
    }

    func read(length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = Data(repeating: 0, count: count)
        let result = try buffer.withUnsafeMutableBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_read_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), SMB2Client.generic_handler, cbPtr
                )
            }
        }
        return Data(buffer.prefix(Int(result)))
    }

    func pread(offset: UInt64, length: Int = 0) throws -> Data {
        precondition(
            length <= UInt32.max, "Length bigger than UInt32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let count = length > 0 ? length : optimizedReadSize
        var buffer = Data(repeating: 0, count: count)
        let result = try buffer.withUnsafeMutableBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_pread_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), offset, SMB2Client.generic_handler,
                    cbPtr
                )
            }
        }
        return buffer.prefix(Int(result))
    }

    var maxWriteSize: Int {
        (try? Int(client.withThreadSafeContext(smb2_get_max_write_size))) ?? -1
    }

    var optimizedWriteSize: Int {
        debugPrint("maxWriteSize --- \(maxWriteSize)")
        debugPrint("minWriteSize --- \(client.minWriteSize)")
        return min(maxWriteSize, client.minWriteSize)
    }

    func write<DataType: DataProtocol>(data: DataType) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let result = try Data(data).withUnsafeBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_write_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), SMB2Client.generic_handler, cbPtr
                )
            }
        }

        return Int(result)
    }

    func pwrite<DataType: DataProtocol>(data: DataType, offset: UInt64) throws -> Int {
        precondition(
            data.count <= Int32.max, "Data bigger than Int32.max can't be handled by libsmb2."
        )

        let handle = try handle.unwrap()
        let result = try Data(data).withUnsafeBytes { buffer in
            try client.async_await { context, cbPtr -> Int32 in
                smb2_pwrite_async(
                    context, handle, buffer.baseAddress, .init(buffer.count), offset, SMB2Client.generic_handler,
                    cbPtr
                )
            }
        }

        return Int(result)
    }

    func fsync() throws {
        let handle = try handle.unwrap()
        try client.async_await { context, cbPtr -> Int32 in
            smb2_fsync_async(context, handle, SMB2Client.generic_handler, cbPtr)
        }
    }
    
    func flock(_ op: LockOperation) throws {
        try client.async_await_pdu { context, dataPtr in
            var element = smb2_lock_element(
                offset: 0,
                length: 0,
                flags: op.smb2Flag,
                reserved: 0
            )
            return withUnsafeMutablePointer(to: &element) { element in
                var request = smb2_lock_request(
                    lock_count: 1,
                    lock_sequence_number: 0,
                    lock_sequence_index: 0,
                    file_id: fileId.uuid,
                    locks: element
                )
                return smb2_cmd_lock_async(context, &request, SMB2Client.generic_handler, dataPtr)
            }
        }
    }
    
    func changeNotify(for type: SMB2FileChangeType) throws {
        try client.async_await_pdu { context, cbPtr in
            var request = smb2_change_notify_request(
                flags: UInt16(type.contains([.recursive]) ? SMB2_CHANGE_NOTIFY_WATCH_TREE : 0),
                output_buffer_length: 32768,
                file_id: fileId.uuid,
                completion_filter: type.completionFilter
            )
            return smb2_cmd_change_notify_async(context, &request, SMB2Client.generic_handler, cbPtr)
        }
    }

    @discardableResult
    func fcntl<DataType: DataProtocol, R: DecodableResponse>(
        command: IOCtl.Command, args: DataType = Data()
    ) throws -> R {
        try withExtendedLifetime(args) { args in
            var inputBuffer = [UInt8](args)
            return try inputBuffer.withUnsafeMutableBytes { buf in
                var req = smb2_ioctl_request(
                    ctl_code: command.rawValue,
                    file_id: fileId.uuid,
                    input_offset: 0, input_count: .init(buf.count),
                    max_input_response: 0,
                    output_offset: 0, output_count: UInt32(client.maximumTransactionSize),
                    max_output_response: 65535,
                    flags: .init(SMB2_0_IOCTL_IS_FSCTL),
                    input: buf.baseAddress
                )
                return try client.async_await_pdu(dataHandler: R.init) {
                    context, cbPtr -> UnsafeMutablePointer<smb2_pdu>? in
                    smb2_cmd_ioctl_async(context, &req, SMB2Client.generic_handler, cbPtr)
                }.data
            }
        }
    }
    
    func fcntl<DataType: DataProtocol>(command: IOCtl.Command, args: DataType = Data()) throws {
        let _: AnyDecodableResponse = try fcntl(command: command, args: args)
    }
}

extension SMB2FileHandle {
    struct SeekWhence: RawRepresentable, Sendable {
        var rawValue: Int32

        static let set = SeekWhence(rawValue: SEEK_SET)
        static let current = SeekWhence(rawValue: SEEK_CUR)
        static let end = SeekWhence(rawValue: SEEK_END)
    }
    
    struct LockOperation: OptionSet, Sendable {
        var rawValue: Int32
        
        static let shared = LockOperation(rawValue: LOCK_SH)
        static let exclusive = LockOperation(rawValue: LOCK_EX)
        static let unlock = LockOperation(rawValue: LOCK_UN)
        static let nonBlocking = LockOperation(rawValue: LOCK_NB)
        
        var smb2Flag: UInt32 {
            var result: UInt32 = 0
            if contains(.shared) { result |= 0x0000_0001 }
            if contains(.exclusive) { result |= 0x0000_0002 }
            if contains(.unlock) { result |= 0x0000_0004 }
            if contains(.nonBlocking) { result |= 0x0000_0010 }
            return result
        }
    }
    
    struct Attributes: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
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
    
    struct LeaseState: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        static let none = Self(rawValue: SMB2_LEASE_NONE)
        static let readCaching = Self(rawValue: SMB2_LEASE_READ_CACHING)
        static let handleCaching = Self(rawValue: SMB2_LEASE_HANDLE_CACHING)
        static let writeCaching = Self(rawValue: SMB2_LEASE_WRITE_CACHING)
    }
    
    enum OpLock: Sendable {
        case none
        case ii
        case exclusive
        case batch
        case lease(state: LeaseState, key: UUID)
        
        var lockLevel: UInt8 {
            switch self {
            case .none:
                .init(SMB2_OPLOCK_LEVEL_NONE)
            case .ii:
                .init(SMB2_OPLOCK_LEVEL_II)
            case .exclusive:
                .init(SMB2_OPLOCK_LEVEL_EXCLUSIVE)
            case .batch:
                .init(SMB2_OPLOCK_LEVEL_BATCH)
            case .lease:
                .init(SMB2_OPLOCK_LEVEL_LEASE)
            }
        }
        
        var leaseState: LeaseState {
            switch self {
            case .lease(let state, _):
                state
            default:
                .none
            }
        }
        
        var leaseContext: CreateLeaseContext? {
            switch self {
            case .lease(let state, let key):
                .init(state: state, key: key)
            default:
                nil
            }
        }
    }
    
    struct ImpersonationLevel: RawRepresentable, Hashable, Sendable {
        var rawValue: UInt32
        
        static let anonymous = Self(rawValue: SMB2_IMPERSONATION_ANONYMOUS)
        static let identification = Self(rawValue: SMB2_IMPERSONATION_IDENTIFICATION)
        static let impersonation = Self(rawValue: SMB2_IMPERSONATION_IMPERSONATION)
        static let delegate = Self(rawValue: SMB2_IMPERSONATION_DELEGATE)
    }
    
    struct Access: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(flags: Int32) {
            switch flags & O_ACCMODE {
            case O_RDWR:
                self = [.read, .write, .delete]
            case O_WRONLY:
                self = [.write, .delete]
            default:
                self = [.read]
            }
            if (flags & O_SYNC) != 0 {
                insert(.synchronize)
            }
        }
        
        /* Access mask common to all objects */
        static let fileReadEA = Self(rawValue: SMB2_FILE_READ_EA)
        static let fileWriteEA = Self(rawValue: SMB2_FILE_WRITE_EA)
        static let fileDeleteChild = Self(rawValue: SMB2_FILE_DELETE_CHILD)
        static let fileReadAttributes = Self(rawValue: SMB2_FILE_READ_ATTRIBUTES)
        static let fileWriteAttributes = Self(rawValue: SMB2_FILE_WRITE_ATTRIBUTES)
        static let delete = Self(rawValue: SMB2_DELETE)
        static let readControl = Self(rawValue: SMB2_READ_CONTROL)
        static let writeDACL = Self(rawValue: SMB2_WRITE_DACL)
        static let writeOwner = Self(rawValue: SMB2_WRITE_OWNER)
        static let synchronize = Self(rawValue: SMB2_SYNCHRONIZE)
        static let acessSystemSecurity = Self(rawValue: SMB2_ACCESS_SYSTEM_SECURITY)
        static let maximumAllowed = Self(rawValue: SMB2_MAXIMUM_ALLOWED)
        static let genericAll = Self(rawValue: SMB2_GENERIC_ALL)
        static let genericExecute = Self(rawValue: SMB2_GENERIC_EXECUTE)
        static let genericWrite = Self(rawValue: SMB2_GENERIC_WRITE)
        static let genericRead = Self(rawValue: SMB2_GENERIC_READ)
        
        /* Access mask unique for file/pipe/printer */
        static let readData = Self(rawValue: SMB2_FILE_READ_DATA)
        static let writeData = Self(rawValue: SMB2_FILE_WRITE_DATA)
        static let appendData = Self(rawValue: SMB2_FILE_APPEND_DATA)
        static let execute = Self(rawValue: SMB2_FILE_EXECUTE)
        
        /* Access mask unique for directories */
        static let listDirectory = Self(rawValue: SMB2_FILE_LIST_DIRECTORY)
        static let addFile = Self(rawValue: SMB2_FILE_ADD_FILE)
        static let addSubdirectory = Self(rawValue: SMB2_FILE_ADD_SUBDIRECTORY)
        static let traverse = Self(rawValue: SMB2_FILE_TRAVERSE)
        
        static let read: Access = [.readData, .readAttributes]
        static let write: Access = [.writeData, .appendData, .fileWriteAttributes, .fileWriteEA, .readControl]
        static let executeList: Access = [.execute, .readAttributes]
        
        private static let readAttributes: Access = [.fileReadAttributes, .fileReadEA, .readControl]
    }
    
    struct ShareAccess: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(flags: Int32) {
            switch flags & O_ACCMODE {
            case O_RDWR:
                self = [.read, .write]
            case O_WRONLY:
                self = [.write]
            default:
                self = [.read]
            }
        }
        
        static let read = Self(rawValue: SMB2_FILE_SHARE_READ)
        static let write = Self(rawValue: SMB2_FILE_SHARE_WRITE)
        static let delete = Self(rawValue: SMB2_FILE_SHARE_DELETE)
    }
    
    struct CreateDisposition: RawRepresentable, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(flags: Int32) {
            if (flags & O_CREAT) != 0 {
                if (flags & O_EXCL) != 0 {
                    self = .create
                } else if (flags & O_TRUNC) != 0 {
                    self = .overwriteIfExists
                } else {
                    self = .openIfExists
                }
            } else {
                if (flags & O_TRUNC) != 0 {
                    self = .overwrite
                } else {
                    self = .open
                }
            }
        }
        
        /// If the file already exists, supersede it. Otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let supersede = Self(rawValue: SMB2_FILE_SUPERSEDE)
        
        /// If the file already exists, return success; otherwise, fail the operation.
        /// MUST NOT be used for a printer object.
        static let open = Self(rawValue: SMB2_FILE_OPEN)
        
        /// If the file already exists, fail the operation; otherwise, create the file.
        static let create = Self(rawValue: SMB2_FILE_CREATE)
        
        /// Open the file if it already exists; otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let openIfExists = Self(rawValue: SMB2_FILE_OPEN_IF)
        
        /// Overwrite the file if it already exists; otherwise, fail the operation.
        /// MUST NOT be used for a printer object.
        static let overwrite = Self(rawValue: SMB2_FILE_OVERWRITE)
        
        /// Overwrite the file if it already exists; otherwise, create the file.
        /// This value SHOULD NOT be used for a printer object.
        static let overwriteIfExists = Self(rawValue: SMB2_FILE_OVERWRITE_IF)
    }
    
    struct CreateOptions: OptionSet, Sendable {
        var rawValue: UInt32
        
        init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        init(flags: Int32) {
            self = []
            if (flags & O_SYNC) != 0 {
                insert(.noIntermediateBuffering)
            }
            if (flags & O_DIRECTORY) != 0 {
                insert(.directoryFile)
            }
            if (flags & O_SYMLINK) != 0 {
                insert(.openReparsePoint)
            }
        }
        
        static let directoryFile = Self(rawValue: SMB2_FILE_DIRECTORY_FILE)
        static let writeThrough = Self(rawValue: SMB2_FILE_WRITE_THROUGH)
        static let sequentialOnly = Self(rawValue: SMB2_FILE_SEQUENTIAL_ONLY)
        static let noIntermediateBuffering = Self(rawValue: SMB2_FILE_NO_INTERMEDIATE_BUFFERING)
        static let synchronousIOAlert = Self(rawValue: SMB2_FILE_SYNCHRONOUS_IO_ALERT)
        static let synchronousIONonAlert = Self(rawValue: SMB2_FILE_SYNCHRONOUS_IO_NONALERT)
        static let nonDirectoryFile = Self(rawValue: SMB2_FILE_NON_DIRECTORY_FILE)
        static let completeIfOplocked = Self(rawValue: SMB2_FILE_COMPLETE_IF_OPLOCKED)
        static let noEAKnowledge = Self(rawValue: SMB2_FILE_NO_EA_KNOWLEDGE)
        static let randomAccess = Self(rawValue: SMB2_FILE_RANDOM_ACCESS)
        static let deleteOnClose = Self(rawValue: SMB2_FILE_DELETE_ON_CLOSE)
        static let openByFileID = Self(rawValue: SMB2_FILE_OPEN_BY_FILE_ID)
        static let openForBackupIntent = Self(rawValue: SMB2_FILE_OPEN_FOR_BACKUP_INTENT)
        static let noCompression = Self(rawValue: SMB2_FILE_NO_COMPRESSION)
        static let openRemoteInstance = Self(rawValue: SMB2_FILE_OPEN_REMOTE_INSTANCE)
        static let openRequiringOplock = Self(rawValue: SMB2_FILE_OPEN_REQUIRING_OPLOCK)
        static let disallowExclusive = Self(rawValue: SMB2_FILE_DISALLOW_EXCLUSIVE)
        static let reserveOpfilter = Self(rawValue: SMB2_FILE_RESERVE_OPFILTER)
        static let openReparsePoint = Self(rawValue: SMB2_FILE_OPEN_REPARSE_POINT)
        static let openNoRecall = Self(rawValue: SMB2_FILE_OPEN_NO_RECALL)
        static let openForFreeSpaceQuery = Self(rawValue: SMB2_FILE_OPEN_FOR_FREE_SPACE_QUERY)
    }
    
    struct CreateLeaseContext: EncodableArgument {
        typealias Element = UInt8
        
        private static let headerLength = 24
        private static let leaseLength = UInt32(SMB2_CREATE_REQUEST_LEASE_SIZE)
        
        var state: LeaseState
        var key: UUID
        var parentKey: UUID?
                
        var regions: [Data] {
            [
                .init(value: 0 as UInt32), // chain offset
                .init(value: 16 as UInt16), // tag offset
                .init(value: 4 as UInt16), // tag length lo
                .init(value: 0 as UInt16), // tag length up
                .init(value: UInt16(Self.headerLength)), // context offset
                .init(value: UInt32(Self.leaseLength)), // context length
                .init(value: 0x5271_4c73 as UInt32),
                .init(value: 0 as UInt32),
                .init(value: key),
                .init(value: state.rawValue),
                .init(value: parentKey != nil ? 0x0000_0004 : 0 as UInt32), // Flags
                .init(value: 0 as UInt64), // LeaseDuration
                .init(value: parentKey ?? .zero),
                .init(value: 4 as UInt16), // Epoch
                .init(value: 0 as UInt16), // Reserved
            ]
        }
        
        init(state: LeaseState, key: UUID, parentKey: UUID? = nil) {
            self.state = state
            self.key = key
            self.parentKey = parentKey
        }
    }
}

extension RawRepresentable where RawValue == UInt32 {
    init(rawValue: Int32) {
        self.init(rawValue: .init(bitPattern: rawValue))!
    }
}

extension RawRepresentable where RawValue: BinaryInteger {
    init(rawValue: Int32) {
        self.init(rawValue: .init(truncatingIfNeeded: rawValue))!
    }
}

extension smb2_stat_64 {
    struct ResourceType: RawRepresentable, Hashable, Sendable {
        var rawValue: UInt32
        
        static let file = Self(rawValue: SMB2_TYPE_FILE)
        static let directory = Self(rawValue: SMB2_TYPE_DIRECTORY)
        static let link = Self(rawValue: SMB2_TYPE_LINK)
        
        var urlResourceType: URLFileResourceType {
            switch self {
            case .directory:
                .directory
            case .file:
                .regular
            case .link:
                .symbolicLink
            default:
                .unknown
            }
        }
    }
    
    var resourceType: ResourceType {
        .init(rawValue: smb2_type)
    }
    
    var isDirectory: Bool {
        resourceType == .directory
    }

    func populateResourceValue(_ dic: inout [URLResourceKey: any Sendable]) {
        dic.reserveCapacity(11 + dic.count)
        dic[.fileSizeKey] = NSNumber(value: smb2_size)
        dic[.linkCountKey] = NSNumber(value: smb2_nlink)
        dic[.documentIdentifierKey] = NSNumber(value: smb2_ino)
        dic[.fileResourceTypeKey] = resourceType.urlResourceType
        dic[.isDirectoryKey] = NSNumber(value: resourceType == .directory)
        dic[.isRegularFileKey] = NSNumber(value: resourceType == .file)
        dic[.isSymbolicLinkKey] = NSNumber(value: resourceType == .link)

        dic[.contentModificationDateKey] = Date(
            timespec(tv_sec: Int(smb2_mtime), tv_nsec: Int(smb2_mtime_nsec))
        )
        dic[.attributeModificationDateKey] = Date(
            timespec(tv_sec: Int(smb2_ctime), tv_nsec: Int(smb2_ctime_nsec))
        )
        dic[.contentAccessDateKey] = Date(
            timespec(tv_sec: Int(smb2_atime), tv_nsec: Int(smb2_atime_nsec))
        )
        dic[.creationDateKey] = Date(
            timespec(tv_sec: Int(smb2_btime), tv_nsec: Int(smb2_btime_nsec))
        )
    }
}

extension UUID {
    static let zero = UUID(uuid: uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
}
