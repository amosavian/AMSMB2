//
//  Extensions.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/21/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

extension Optional {
    func unwrap() throws -> Wrapped {
        guard let self = self else {
            throw POSIXError(.ENODATA, description: "Invalid/Empty data.")
        }
        return self
    }
}

extension Optional where Wrapped: SMB2Context {
    func unwrap() throws -> SMB2Context {
        guard let self = self, self.fileDescriptor >= 0 else {
            throw POSIXError(.ENOTCONN, description: "SMB2 server not connected.")
        }
        return self
    }
}

extension RawRepresentable where RawValue == UInt32 {
    init(_ rawValue: Int32) {
        self.init(rawValue: .init(bitPattern: rawValue))!
    }
}

extension RawRepresentable where RawValue == UInt16 {
    init(_ rawValue: Int16) {
        self.init(rawValue: .init(bitPattern: rawValue))!
    }
}

extension POSIXError {
    static func throwIfError<Number: SignedInteger>(_ result: Number, description: String?) throws {
        guard result < 0 else { return }
        let errno = Int32(-result)
        let errorDesc = description.map { "Error code \(errno): \($0)" }
        throw POSIXError(.init(errno), description: errorDesc)
    }

    static func throwIfErrorStatus(_ status: UInt32) throws {
        if status & SMB2_STATUS_SEVERITY_MASK == SMB2_STATUS_SEVERITY_ERROR {
            let errorNo = nterror_to_errno(status)
            let description = nterror_to_str(status).map(String.init(cString:)) ?? "Unknown"
            throw POSIXError(.init(errorNo), description: "Error 0x\(String(status, radix: 16, uppercase: true)): \(description)")
        }
    }

    init(_ code: POSIXError.Code, description: String?) {
        let userInfo: [String: Any] =
            description.map { [NSLocalizedFailureReasonErrorKey: $0] } ?? [:]
        self = POSIXError(code, userInfo: userInfo)
    }
}

extension POSIXErrorCode {
    init(_ code: Int32) {
        self = POSIXErrorCode(rawValue: code) ?? .ECANCELED
    }
}

/// The conformant must be able to be initialized with no arguments.
///
/// This is also known as the default initial value.
protocol EmptyInitializable {
    init()
}

/// Booleans can be initialized with no arguments and it would be `false` by default.
extension Bool: EmptyInitializable {}

extension Dictionary where Key == URLResourceKey {
    private func value<T>(forKey key: Key) -> T? {
        self[key] as? T
    }

    private func value<T>(forKey key: Key) -> T where T: EmptyInitializable {
        self[key] as? T ?? T()
    }

    public var name: String? {
        value(forKey: .nameKey)
    }

    public var path: String? {
        value(forKey: .pathKey)
    }

    public var fileResourceType: URLFileResourceType? {
        value(forKey: .fileResourceTypeKey)
    }

    public var isDirectory: Bool {
        value(forKey: .isDirectoryKey)
    }

    public var isRegularFile: Bool {
        value(forKey: .isRegularFileKey)
    }

    public var isSymbolicLink: Bool {
        value(forKey: .isSymbolicLinkKey)
    }

    public var fileSize: Int64? {
        value(forKey: .fileSizeKey)
    }

    public var attributeModificationDate: Date? {
        value(forKey: .attributeModificationDateKey)
    }

    public var contentModificationDate: Date? {
        value(forKey: .contentModificationDateKey)
    }

    public var contentAccessDate: Date? {
        value(forKey: .contentAccessDateKey)
    }

    public var creationDate: Date? {
        value(forKey: .creationDateKey)
    }
}

extension Array where Element == [URLResourceKey: Any] {
    func sortedByPath(_ comparison: ComparisonResult) -> [[URLResourceKey: Any]] {
        sorted {
            guard let firstPath = $0.path, let secPath = $1.path else {
                return false
            }
            return firstPath.localizedStandardCompare(secPath) == comparison
        }
    }

    var overallSize: Int64 {
        reduce(0) { result, value -> Int64 in
            guard value.isRegularFile else { return result }
            return result + (value.fileSize ?? 0)
        }
    }
}

extension Array where Element == SMB2Share {
    func map(enumerateHidden: Bool) -> [(name: String, comment: String)] {
        var shares = self
        if enumerateHidden {
            shares = shares.filter { $0.props.type == .diskTree }
        } else {
            shares = shares.filter { !$0.props.isHidden && $0.props.type == .diskTree }
        }
        return shares.map { ($0.name, $0.comment) }
    }
}

extension RangeExpression where Bound: FixedWidthInteger {
    var int64Range: Range<Int64> {
        let range: Range<Bound> = relative(to: 0..<Bound.max)
        let lower = Int64(exactly: range.lowerBound) ?? (Int64.max - 1)
        let upper = Int64(exactly: range.upperBound) ?? Int64.max
        return lower..<upper
    }
}

extension Date {
    init(_ timespec: timespec) {
        self.init(
            timeIntervalSince1970: TimeInterval(timespec.tv_sec) + TimeInterval(
                timespec.tv_nsec / 1000
            ) / TimeInterval(USEC_PER_SEC)
        )
    }
}

extension timespec {
    init(_ date: Date) {
        let interval = date.timeIntervalSince1970
        self.init(tv_sec: .init(interval), tv_nsec: Int(interval.truncatingRemainder(dividingBy: 1) * Double(NSEC_PER_SEC)))
    }
}

extension Data {
    init<T: FixedWidthInteger>(value: T) {
        var value = value.littleEndian
        let bytes = Swift.withUnsafeBytes(of: &value) { Array($0) }
        self.init(bytes)
    }

    mutating func append<T: FixedWidthInteger>(value: T) {
        append(Data(value: value))
    }

    init(value uuid: UUID) {
        self.init([
            uuid.uuid.3, uuid.uuid.2, uuid.uuid.1, uuid.uuid.0,
            uuid.uuid.5, uuid.uuid.4, uuid.uuid.7, uuid.uuid.6,
            uuid.uuid.8, uuid.uuid.9, uuid.uuid.10, uuid.uuid.11,
            uuid.uuid.12, uuid.uuid.13, uuid.uuid.14, uuid.uuid.15,
        ])
    }

    mutating func append(value uuid: UUID) {
        append(Data(value: uuid))
    }

    func scanValue<T: FixedWidthInteger>(offset: Int, as _: T.Type) -> T? {
        guard count >= offset + MemoryLayout<T>.size else { return nil }
        return T(littleEndian: withUnsafeBytes { $0.load(fromByteOffset: offset, as: T.self) })
    }

    func scanInt<T: FixedWidthInteger>(offset: Int, as _: T.Type) -> Int? {
        scanValue(offset: offset, as: T.self).map(Int.init)
    }
}

extension String {
    var canonical: String {
        trimmingCharacters(in: .init(charactersIn: "/\\"))
    }

    func fileURL(_ isDirectory: Bool = false) -> URL {
        if #available(macOS 13.0, iOS 16.0, tvOS 16.0, watchOS 9.0, *) {
            return .init(
                filePath: self, directoryHint: isDirectory ? .isDirectory : .notDirectory,
                relativeTo: .init(filePath: "/")
            )
        } else {
            return .init(
                fileURLWithPath: self, isDirectory: isDirectory,
                relativeTo: .init(fileURLWithPath: "/")
            )
        }
    }
}

extension Stream {
    func withOpenStream(_ handler: () throws -> Void) rethrows {
        let shouldCloseStream = streamStatus == .notOpen
        if streamStatus == .notOpen {
            open()
        }
        defer {
            if shouldCloseStream {
                close()
            }
        }
        try handler()
    }
}

extension InputStream {
    func readData(maxLength length: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: length)
        let result = read(&buffer, maxLength: buffer.count)
        if result < 0 {
            throw streamError ?? POSIXError(.EIO, description: "Unknown stream error.")
        } else {
            return Data(buffer.prefix(result))
        }
    }
}

extension OutputStream {
    func write<DataType: DataProtocol>(_ data: DataType) throws -> Int {
        var buffer = Array(data)
        let result = write(&buffer, maxLength: buffer.count)
        if result < 0 {
            throw streamError ?? POSIXError(.EIO, description: "Unknown stream error.")
        } else {
            return result
        }
    }
}

func asyncHandler(_ continuation: CheckedContinuation<Void, any Error>) -> @Sendable (_ error: (any Error)?) -> Void {
    { error in
        if let error = error {
            continuation.resume(throwing: error)
            return
        }
        continuation.resume(returning: ())
    }
}

func asyncHandler<T>(_ continuation: CheckedContinuation<T, any Error>) -> @Sendable (Result<T, any Error>) -> Void {
    { result in
        continuation.resume(with: result)
    }
}
