//
//  Stream.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/14/24.
//  Copyright © 2024 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation

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
    
    func withOpenStream(_ handler: () async throws -> Void) async rethrows {
        let shouldCloseStream = streamStatus == .notOpen
        if streamStatus == .notOpen {
            open()
        }
        defer {
            if shouldCloseStream {
                close()
            }
        }
        try await handler()
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

extension AsyncThrowingStream where Element == Data, Failure == any Error {
    init(url: URL, chunkSize: Int = 1_048_576) {
        self.init { continuation in
            do {
                let fileHandle = try FileHandle(forReadingFrom: url)
                defer {
                    try? fileHandle.close()
                }

                while true {
                    let data: Data?
                    if #available(macOS 10.15.4, iOS 13.4, watchOS 6.2, tvOS 13.4, *) {
                        data = try fileHandle.read(upToCount: chunkSize)
                    } else {
                        data = fileHandle.readData(ofLength: chunkSize)
                    }
                    if let data = data, !data.isEmpty {
                        continuation.yield(data)
                    } else {
                        break
                    }
                }
                continuation.finish()
            } catch {
                continuation.finish(throwing: error)
            }
        }
    }
    
    func write(toFileAt file: URL) async throws {
        guard let stream = OutputStream(url: file, append: false) else {
            throw POSIXError(.EINVAL, description: "File not fould")
        }
        try await stream.withOpenStream {
            for try await data in self {
                _ = try stream.write(data)
            }
        }
    }
}

public class AsyncInputStream<Seq>: InputStream, @unchecked Sendable where Seq: AsyncSequence, Seq.Element: DataProtocol {
    private var stream: Seq
    private var iterator: Seq.AsyncIterator
    private var buffer: Data?
    private var bufferOffset = 0
    private var _streamError: (any Error)?
    private var _streamStatus: Stream.Status = .notOpen
    private let bufferLock = NSLock()

    init(stream: Seq) {
        self.stream = stream
        self.iterator = stream.makeAsyncIterator()
        super.init(data: Data())
        prefetchData()
    }

    override public var streamStatus: Stream.Status {
        _streamStatus
    }

    override public func open() {
        _streamStatus = .open
    }

    override public func close() {
        _streamStatus = .closed
    }
    
    override public var streamError: (any Error)? {
        _streamError
    }

    override public func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
        switch streamStatus {
        case .notOpen, .closed, .error, .opening:
            return -1
        case .atEnd:
            return 0
        case .open, .reading, .writing:
            break
        @unknown default:
            break
        }
        
        bufferLock.lock()
        defer { bufferLock.unlock() }

        if self.buffer == nil || bufferOffset >= self.buffer!.count {
            return -1
        }

        let bytesToCopy = min(len, self.buffer!.count - bufferOffset)
        self.buffer!.copyBytes(to: buffer, from: bufferOffset..<(bufferOffset + bytesToCopy))
        bufferOffset += bytesToCopy
        
        if bufferOffset == self.buffer!.count {
            _streamStatus = .atEnd
        }

        return bytesToCopy
    }

    override public var hasBytesAvailable: Bool {
        bufferLock.lock()
        defer { bufferLock.unlock() }
        return buffer != nil && bufferOffset < buffer!.count || streamStatus == .open
    }

    private func prefetchData() {
        Task {
            do {
                while let data = try await iterator.next() {
                    bufferLock.withLock {
                        if self.buffer == nil {
                            self.buffer = Data(data)
                        } else {
                            self.buffer!.append(contentsOf: data)
                        }
                    }
                }
            } catch {
                bufferLock.withLock {
                    _streamStatus = .error
                }
            }
        }
    }
}
