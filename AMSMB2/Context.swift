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
#if canImport(System)
import System
#else
import SystemPackage
#endif

extension FileDescriptor {
    static var invalid: FileDescriptor { .init(rawValue: -1) }
    var isValidSocket: Bool { rawValue > 0 }
}

/// Provides synchronous operation on SMB2
final class SMB2Client: CustomDebugStringConvertible, CustomReflectable, @unchecked Sendable {
    var context: UnsafeMutablePointer<smb2_context>?
    private var _context_lock = NSRecursiveLock()
    
    init() throws {
        self.context = try smb2_init_context().unwrap()
        // Every async request hands libsmb2 a +1 that its callback consumes exactly once (see
        // `generic_handler`). With passthrough ON, socket.c dispatches the interim
        // `SMB2_STATUS_PENDING` reply through that same callback WITHOUT delisting the PDU, so the
        // real reply dispatches a second time and over-releases the box. Pinned here rather than
        // trusted to libsmb2's default, so the ownership contract holds by construction instead of
        // by nobody having flipped it yet.
        passthrough = false
    }

    deinit {
        guard context != nil else { return }
        if isActive {
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
        c.append((label: "isConnected", value: isActive))
        c.append((label: "timeout", value: timeout))

        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
}

// MARK: Setting manipulation

extension SMB2Client {
    var opaque: UnsafeMutableRawPointer? {
        get {
            try? smb2_get_opaque(context.unwrap())
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_opaque(context, newValue)
            }
        }
    }
    
    var isActive: Bool {
        (try? smb2_context_active(context.unwrap())) == 1 && fileDescriptor.isValidSocket
    }
    
    var timeout: TimeInterval {
        get {
            TimeInterval(context?.pointee.timeout ?? 0)
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_timeout(context, Int32(newValue))
            }
        }
    }
    
    var workstation: String {
        get {
            smb2_get_workstation(context).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_workstation(context, newValue)
            }
        }
    }
    
    var domain: String {
        get {
            smb2_get_domain(context).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_domain(context, newValue)
            }
        }
    }
    
    var user: String {
        get {
            smb2_get_user(context).map(String.init(cString:)) ?? ""
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
                smb2_set_password(context, newValue != "" ? newValue : nil)
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
        (try? smb2_get_dialect(context.unwrap())).map { Version(rawValue: UInt32($0)) } ?? .any
    }
    
    var passthrough: Bool {
        get {
            var result: CInt = 0
            smb2_get_passthrough(context, &result)
            return result != 0
        }
        set {
            smb2_set_passthrough(context, newValue ? 1 : 0)
        }
    }
    
    var fileDescriptor: FileDescriptor {
        do {
            return try .init(rawValue: smb2_get_fd(context.unwrap()))
        } catch {
            return .invalid
        }
    }

    var errorString: String? {
        smb2_get_error(context).map(String.init(cString:))
    }
    
    var ntError: NTStatus {
        .init(rawValue: smb2_get_nterror(context))
    }
    
    var errno: Errno {
        ntError.errno
    }
    
    var maximumTransactionSize: Int {
        (context?.pointee.max_transact_size).map(Int.init) ?? 65535
    }

    func whichEvents() throws -> Int16 {
        try Int16(truncatingIfNeeded: smb2_which_events(context.unwrap()))
    }

    func service(revents: Int32) throws {
        // Held here rather than left to the caller: the failure path destroys the context, and no
        // other thread may be reading it meanwhile. The lock is recursive, so the usual call from
        // inside `withThreadSafeContext` still works.
        _context_lock.lock()
        defer { _context_lock.unlock() }
        let result = smb2_service(context, revents)
        if result < 0 {
            // Read the error out while the context is still readable.
            let description = errorString
            // Clear the pointer BEFORE destroying, never after — `deinit` already gets this order
            // right and this path did not.
            //
            // `smb2_destroy_context` dispatches `SMB2_STATUS_SHUTDOWN` to every PDU left in the out,
            // pending and wait queues, freeing each as it goes. Those callbacks run arbitrary Swift:
            // `generic_handler` releases the request box, and anything the box was keeping alive is
            // released with it. If that lands on the last reference to this client, `deinit` runs
            // part-way through the walk and destroys the very context being walked — a second pass
            // over half-freed queues. `_context_lock` cannot stop it, because it is recursive and
            // the re-entry is on the same thread.
            //
            // Nil first and that second pass becomes a no-op against `deinit`'s own nil guard.
            let doomed = context
            context = nil
            smb2_destroy_context(doomed)
            try POSIXError.throwIfError(result, description: description)
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
        _=try? async_await { context, cbPtr -> Int32 in
            smb2_disconnect_share_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }

    func echo() throws {
        if !isActive {
            throw POSIXError(.socketNotConnected, description: nil)
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
        let recvBindData = try srvsvc.read(toAbsoluteOffset: 0, length: Int(Int16.max))
        try MSRPC.validateBindData(recvBindData)

        // NetShareEnum request, Level 1 mean we need share name and remark.
        _ = try srvsvc.write(toAbsoluteOffset: 0, data: MSRPC.NetShareEnumAllRequest(serverName: server!))
        let recvData = try srvsvc.read(toAbsoluteOffset: 0)
        return try MSRPC.NetShareEnumAllLevel1(data: recvData).shares
    }
}

// MARK: File information

extension SMB2Client {
    // libsmb2 keeps this pointer in its own `stat_data` and `getinfo_cb_2`/`_3` write through it
    // when the reply lands — for an abandoned request, long after this call returned. So the
    // storage belongs to the request, not to this frame.
    func stat(_ path: String) throws -> smb2_stat_64 {
        let st = RequestValue(smb2_stat_64())
        try async_await(owning: [st]) { context, cbPtr -> Int32 in
            smb2_stat_async(
                context, path.trimmedPath, st.pointer, SMB2Client.generic_handler, cbPtr
            )
        }
        return st.value
    }

    // Same request-owned out-parameter as `stat`.
    func statvfs(_ path: String) throws -> smb2_statvfs {
        let st = RequestValue(smb2_statvfs())
        try async_await(owning: [st]) { context, cbPtr -> Int32 in
            smb2_statvfs_async(
                context, path.trimmedPath, st.pointer, SMB2Client.generic_handler, cbPtr
            )
        }
        return st.value
    }

    func readlink(_ path: String) throws -> String {
        try async_await(dataHandler: String.init) { context, cbPtr -> Int32 in
            smb2_readlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }.data
    }
    
    func symlink(_ path: String, to destination: String) throws {
        let file = try SMB2FileHandle(path: path, .readWrite, options: [.create, .exclusiveLock, .symlink, .sync], on: self)
        let reparse = IOCtl.SymbolicLinkReparse(path: destination, isRelative: true)
        try file.fcntl(command: .setReparsePoint, args: reparse)
    }
}

// MARK: File operation

extension SMB2Client {
    func mkdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_mkdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }

    func rmdir(_ path: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rmdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }
    
    func unlink(_ path: String, type: smb2_stat_64.ResourceType = .file) throws {
        switch type {
        case .directory:
            throw POSIXError(.invalidArgument, description: "Use rmdir() to delete a directory.")
        case .file:
            try async_await { context, cbPtr -> Int32 in
                smb2_unlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
            }
        case .link:
            let file = try SMB2FileHandle(path: path, .readWrite, options: [.symlink], on: self)
            try file.setInfo(smb2_file_disposition_info(delete_pending: 1), infoClass: .disposition)
        default:
            preconditionFailure("Not supported file type.")
        }
    }

    func rename(_ path: String, to newPath: String) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_rename_async(
                context, path.trimmedPath, newPath.trimmedPath, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func resize(_ path: String, to newSize: UInt64) throws {
        try async_await { context, cbPtr -> Int32 in
            smb2_truncate_async(
                context, path.trimmedPath, newSize, SMB2Client.generic_handler, cbPtr
            )
        }
    }
}

// MARK: Async operation handler

extension SMB2Client {
    /// One request's callback state, owned by the request itself.
    ///
    /// The box is a heap object handed to libsmb2 as a +1 retain, and it also owns every allocation
    /// the request lends libsmb2 a raw pointer into (`owned`) — libsmb2's own intermediate
    /// callbacks (`getinfo_cb_2`/`_3`) write through those pointers before they ever reach
    /// `generic_handler`. So an abandoned request outlives its Swift call safely: its memory stays
    /// valid until a callback finally fires, and dies with it.
    ///
    /// The +1 is consumed at most once. Every dispatch libsmb2 makes for a queued request — a
    /// reply, PDU retirement, or `smb2_destroy_context`'s shutdown walk — is one call, with one
    /// exception: the walk invokes only the head of a compound chain (init.c) and `smb2_free_pdu`
    /// frees the rest of the chain silently (pdu.c), so a request whose reporting callback sits
    /// behind the head is never dispatched at all. That box leaks; it never dangles.
    ///
    /// `_context_lock` is what serializes all of it — box creation, callback dispatch (only ever
    /// out of `smb2_service`), and `wait_for_reply`'s polling all run under that lock.
    private class CBData: @unchecked Sendable {
        var result: Int32 = .init(NTStatus.success.rawValue)
        var isFinished: Bool = false
        var dataHandler: ((UnsafeMutableRawPointer?) -> Void)?
        /// Storage the C request holds raw pointers into, kept alive by the request.
        var owned: [AnyObject] = []
        var status: NTStatus {
            NTStatus(rawValue: result)
        }
    }
    
    private class AsyncCallbackData<T> {
        var continuation: CheckedContinuation<T, any Error>
        
        init(continuation: CheckedContinuation<T, any Error>) {
            self.continuation = continuation
        }
    }
    
    private func wait(_ cb: inout CBData) async throws {
        let startDate = Date()
        let source = switch try whichEvents() {
        case Int16(POLL_IN):
            DispatchSource.makeReadSource(fileDescriptor: fileDescriptor.rawValue)
        case Int16(POLL_OUT):
            DispatchSource.makeWriteSource(fileDescriptor: fileDescriptor.rawValue)
        default:
            throw POSIXError(errno, description: errorString)
        }
        source.setEventHandler {
            return
        }
        
    }
    private func wait_for_reply(_ cb: CBData) throws {
        let startDate = Date()
        while !cb.isFinished {
            var pfd = pollfd()
            pfd.fd = fileDescriptor.rawValue
            pfd.events = try whichEvents()
            if pfd.fd < 0 || (poll(&pfd, 1, 1000) < 0 && errno != .resourceTemporarilyUnavailable) {
                throw POSIXError(errno, description: errorString)
            }
            
            if pfd.revents == 0 {
                if timeout > 0, Date().timeIntervalSince(startDate) > timeout {
                    throw POSIXError(.timedOut, description: nil)
                }
                continue
            }
            
            try service(revents: Int32(pfd.revents))
        }
    }

    // The callback consumes the +1 the request was queued with, so the box and everything it owns
    // dies with its one dispatch — including the `SMB2_STATUS_SHUTDOWN` dispatch
    // `smb2_destroy_context` makes for every request still in its queues.
    //
    // This is why `init` pins `passthrough` off: with it set, an interim `SMB2_STATUS_PENDING` reply
    // is dispatched through this same callback without delisting the PDU (socket.c), which would
    // consume the +1 twice.
    static let generic_handler: smb2_command_cb = { _, status, command_data, cbdata in
        guard let cbdata else { return }
        let cb = Unmanaged<CBData>.fromOpaque(cbdata).takeRetainedValue()
        if NTStatus(rawValue: status) != .success {
            cb.result = status
        }
        cb.dataHandler?(command_data)
        cb.isFinished = true
    }

    typealias ContextHandler<R> = (_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?)
        throws -> R
    typealias UnsafeContextHandler<R> = (
        _ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?
    ) throws -> R

    /// Builds one request box and hands libsmb2 the +1 it will consume in the callback. `owning` is
    /// the storage the C call is about to borrow raw pointers into — see `CBData` for why it may
    /// not live in the caller's frame.
    private func makeRequestBox<DataType>(
        owning: [AnyObject],
        dataHandler: @escaping ContextHandler<DataType>
    ) -> (cb: CBData, cbPtr: UnsafeMutableRawPointer, outcome: RequestOutcome<DataType>) {
        let cb = CBData()
        cb.owned = owning
        let outcome = RequestOutcome<DataType>()
        // `unowned(unsafe)`, never strong: an abandoned request's box outlives its Swift call, and
        // a strong client reference would mean the client never deinits, so
        // `smb2_destroy_context` never runs, so the very callback that frees the box never fires.
        // Safe because libsmb2 can only dispatch through a live context, and the only places a
        // context is destroyed are inside the client itself (`deinit`, `service`) while it is still
        // in memory. For the same reason no `dataHandler` may retain the client: the shutdown walk
        // runs from `deinit`, so the `self` it dispatches with is already mid-deallocation.
        cb.dataHandler = { [unowned(unsafe) self] ptr in
            do {
                outcome.data = try dataHandler(self, ptr)
            } catch {
                outcome.error = error
            }
        }
        return (cb, Unmanaged.passRetained(cb).toOpaque(), outcome)
    }

    /// Releases the +1 above when — and only when — nothing will ever consume it.
    ///
    /// `isFinished` is the discriminator: libsmb2 has failure paths that invoke the callback AND
    /// still return an error (`smb2_stat_async`'s compound-close allocation failure, for one), so
    /// releasing on the error alone would be an over-release.
    private func releaseUnconsumedRequest(_ cb: CBData, _ cbPtr: UnsafeMutableRawPointer) {
        guard !cb.isFinished else { return }
        Unmanaged<CBData>.fromOpaque(cbPtr).release()
    }

    /// Throws whatever failure `generic_handler` recorded, in the encoding libsmb2 reported it in.
    ///
    /// A command callback receives one of two things: `-errno` from libsmb2's path-level wrappers
    /// (libsmb2.c), or a raw NT status from the paths that dispatch the callback themselves — PDU
    /// retirement passes `SMB2_STATUS_IO_TIMEOUT` (pdu.c) and the shutdown walk passes
    /// `SMB2_STATUS_SHUTDOWN` (init.c). The two never collide: an errno is a small number, an NT
    /// status carries its severity in the top bits. Reading a status as an errno would report a
    /// retired request as an unrelated code instead of `ETIMEDOUT`.
    private func throwIfCallbackFailed(_ cb: CBData) throws {
        // Lowest value still readable as `-errno`; every NT status is far below it.
        let errnoFloor: Int32 = -4096
        guard cb.result < 0 else { return }
        if cb.result > errnoFloor {
            try POSIXError.throwIfError(cb.result, description: errorString)
        } else {
            try cb.status.throwIfError()
        }
    }

    @discardableResult
    func async_await(
        owning: [AnyObject] = [],
        execute handler: UnsafeContextHandler<Int32>
    )
        throws -> Int32
    {
        try async_await(owning: owning, dataHandler: { _, _ in }, execute: handler).result
    }

    @discardableResult
    func async_await<DataType>(
        owning: [AnyObject] = [],
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<Int32>
    )
        throws -> (result: Int32, data: DataType)
    {
        try withThreadSafeContext { context -> (Int32, DataType) in
            let (cb, cbPtr, outcome) = makeRequestBox(owning: owning, dataHandler: dataHandler)
            let result: Int32
            do {
                result = try handler(context, cbPtr)
            } catch {
                releaseUnconsumedRequest(cb, cbPtr)
                throw error
            }
            // A negative return means the request was never queued, so past this point the box is
            // libsmb2's to consume — including when `wait_for_reply` gives up below.
            if result < 0 { releaseUnconsumedRequest(cb, cbPtr) }
            try POSIXError.throwIfError(result, description: errorString)
            try wait_for_reply(cb)

            try throwIfCallbackFailed(cb)
            if let error = outcome.error { throw error }
            return try (cb.result, outcome.data.unwrap())
        }
    }

    @discardableResult
    func async_await_pdu(
        owning: [AnyObject] = [],
        execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>
    )
        throws -> UInt32
    {
        try async_await_pdu(owning: owning, dataHandler: { _, _ in }, execute: handler).status
    }

    @discardableResult
    func async_await_pdu<DataType>(
        owning: [AnyObject] = [],
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>
    )
        throws -> (status: UInt32, data: DataType)
    {
        try withThreadSafeContext { context -> (UInt32, DataType) in
            let (cb, cbPtr, outcome) = makeRequestBox(owning: owning, dataHandler: dataHandler)
            let pdu: UnsafeMutablePointer<smb2_pdu>
            do {
                pdu = try handler(context, cbPtr).unwrap()
            } catch {
                // No PDU means nothing holds the box — `smb2_cmd_*_async` allocates but does not
                // queue, so a nil return leaves the request non-existent.
                releaseUnconsumedRequest(cb, cbPtr)
                throw error
            }
            smb2_queue_pdu(context, pdu)
            try wait_for_reply(cb)

            try cb.status.throwIfError()
            if let error = outcome.error { throw error }
            return try (cb.status.rawValue, outcome.data.unwrap())
        }
    }
}

/// What one request's data handler produced, on the heap.
///
/// The box belongs to the request rather than to the frame that started it, so a late callback
/// writes into memory that is still alive.
///
/// Serialized by `_context_lock`: only the data handler writes it, from a libsmb2 dispatch.
private final class RequestOutcome<DataType>: @unchecked Sendable {
    var data: DataType?
    var error: (any Error)?
}

/// One C value a request writes its result into (`stat`'s `smb2_stat_64`, and so on).
///
/// libsmb2 keeps the pointer in its own heap state (`struct stat_data`) and writes through it when
/// the reply lands, so the value must outlive the Swift call that asked for it. Handed to
/// `async_await(owning:)`, which keeps it alive for exactly as long as the callback can still fire.
///
/// Serialized by `_context_lock`: libsmb2 writes through `pointer` only while dispatching under it.
final class RequestValue<Value>: @unchecked Sendable {
    let pointer: UnsafeMutablePointer<Value>

    init(_ initial: Value) {
        pointer = .allocate(capacity: 1)
        pointer.initialize(to: initial)
    }

    /// The result, copied out. Read only after the request completed successfully.
    var value: Value {
        pointer.pointee
    }

    deinit {
        pointer.deinitialize(count: 1)
        pointer.deallocate()
    }
}

/// One byte buffer a request reads from or writes into.
///
/// libsmb2 adds the caller's buffer to the PDU's iovector WITHOUT copying it (`smb2_add_iovector`
/// with a nil free function, in smb2-cmd-read.c / smb2-cmd-write.c / smb2-cmd-ioctl.c), so the
/// reply is scattered straight into it and an outgoing payload is read straight out of it — both
/// possibly long after the Swift call returned. Handed to `async_await(owning:)` to live that long.
///
/// Serialized by `_context_lock`: libsmb2 touches the bytes only while servicing the context.
final class RequestBuffer: @unchecked Sendable {
    let pointer: UnsafeMutablePointer<UInt8>
    let count: Int

    /// A zero-filled buffer for a reply to be read into.
    init(count: Int) {
        self.count = max(0, count)
        pointer = .allocate(capacity: max(1, self.count))
        pointer.initialize(repeating: 0, count: max(1, self.count))
    }

    /// A private copy of an outgoing payload.
    init<DataType: DataProtocol>(copying bytes: DataType) {
        let byteCount = bytes.count
        count = byteCount
        pointer = .allocate(capacity: max(1, byteCount))
        guard byteCount > 0 else {
            pointer.initialize(repeating: 0, count: 1)
            return
        }
        let destination = pointer
        Data(bytes).withUnsafeBytes { source in
            destination.initialize(
                from: source.baseAddress!.assumingMemoryBound(to: UInt8.self), count: byteCount
            )
        }
    }

    /// The first `length` bytes, copied out.
    func data(count length: Int) -> Data {
        Data(bytes: pointer, count: min(max(0, length), count))
    }

    deinit {
        pointer.deinitialize(count: max(1, count))
        pointer.deallocate()
    }
}

extension SMB2Client {
    struct NegotiateSigning: OptionSet, Sendable, CustomStringConvertible {
        var rawValue: UInt16
        
        var description: String {
            var result: [String] = []
            if contains(.enabled) { result.append("Enabled") }
            if contains(.required) { result.append("Required") }
            return result.joined(separator: ", ")
        }
        
        static let enabled = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_ENABLED)
        static let required = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_REQUIRED)
    }

    typealias Version = smb2_negotiate_version
    typealias Security = smb2_sec
}

extension SMB2.smb2_negotiate_version: Swift.Hashable, Swift.CustomStringConvertible {
    static let any = SMB2_VERSION_ANY
    static let v2 = SMB2_VERSION_ANY2
    static let v3 = SMB2_VERSION_ANY3
    static let v2_02 = SMB2_VERSION_0202
    static let v2_10 = SMB2_VERSION_0210
    static let v3_00 = SMB2_VERSION_0300
    static let v3_02 = SMB2_VERSION_0302
    static let v3_11 = SMB2_VERSION_0311
    
    public var description: String {
        switch self {
        case .any: return "Any"
        case .v2: return "2.0"
        case .v3: return "3.0"
        case .v2_02: return "2.02"
        case .v2_10: return "2.10"
        case .v3_00: return "3.00"
        case .v3_02: return "3.02"
        case .v3_11: return "3.11"
        default: return "Unknown"
        }
    }

    static func ==(lhs: smb2_negotiate_version, rhs: smb2_negotiate_version) -> Bool {
        lhs.rawValue == rhs.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}

extension SMB2.smb2_sec: Swift.Hashable, Swift.CustomStringConvertible {
    static let undefined = SMB2_SEC_UNDEFINED
    static let ntlmSsp = SMB2_SEC_NTLMSSP
    static let kerberos5 = SMB2_SEC_KRB5
    
    public var description: String {
        switch self {
        case .undefined: return "Undefined"
        case .ntlmSsp: return "NTLM SSP"
        case .kerberos5: return "Kerberos5"
        default: return "Unknown"
        }
    }

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

struct NTStatus: LocalizedError, Hashable, CustomStringConvertible, Sendable {
    enum Severity: UInt32, Hashable, CustomStringConvertible, Sendable {
        case success
        case info
        case warning
        case error
        
        var description: String {
            switch self {
            case .success: return "Success"
            case .info: return "Info"
            case .warning: return "Warning"
            case .error: return "Error"
            }
        }
        
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
    
    var description: String {
        "Error 0x\(String(rawValue, radix: 16, uppercase: true)): \(localizedDescription)"
    }
    
    var errorDescription: String? {
        nterror_to_str(rawValue).map(String.init(cString:))
    }
    
    var errno: Errno {
        .init(rawValue: nterror_to_errno(rawValue))
    }
    
    var severity: Severity {
        .init(status: self)
    }
    
    func throwIfError() throws {
        if severity == .error {
            throw POSIXError(errno,description: description)
        }
    }
    
    static let success = Self(rawValue: SMB2_STATUS_SUCCESS)
}
