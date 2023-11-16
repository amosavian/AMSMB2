//
//  fsctl.swift
//  AMSMB2
//
//  Created by Amir Abbas on 4/17/1397 AP.
//  Copyright © 1397 AP Mousavian. All rights reserved.
//

import Foundation
import SMB2

protocol IOCtlArgument: ContiguousBytes & DataProtocol where Index == Int, Element == UInt8 {}

extension IOCtlArgument {
    var startIndex: Int {
        return 0
    }

    var endIndex: Int {
        return regions.map(\.count).reduce(0, +)
    }

    subscript(index: Int) -> UInt8 {
        get {
            let data = regions.joined()
            let index = data.index(data.startIndex, offsetBy: index)
            return data[index]
        }
    }

    subscript(bounds: Range<Index>) -> Data {
        let data = regions.joined()
        let start = data.index(data.startIndex, offsetBy: bounds.lowerBound)
        let end = data.index(data.startIndex, offsetBy: bounds.upperBound)
        return Data(data[start..<end])
    }

    func index(after i: Int) -> Int {
        return i + 1
    }
    
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Data(regions.joined()).withUnsafeBytes(body)
    }
}

protocol IOCtlReply {
    init(data: Data) throws
}

struct AnyIOCtlReply: IOCtlReply {
    private let data: Data
    
    init(data: Data) {
        self.data = data
    }
}

struct IOCtl {

    struct Command: RawRepresentable, Equatable, Hashable {
        var rawValue: UInt32

        static let dfsGetReferrals = Command(rawValue: UInt32(SMB2_FSCTL_DFS_GET_REFERRALS))
        static let pipePeek = Command(rawValue: UInt32(SMB2_FSCTL_PIPE_PEEK))
        static let pipeWait = Command(rawValue: UInt32(SMB2_FSCTL_PIPE_WAIT))
        static let pipeTranceive = Command(rawValue: UInt32(SMB2_FSCTL_PIPE_TRANSCEIVE))
        static let srvCopyChunk = Command(rawValue: UInt32(SMB2_FSCTL_SRV_COPYCHUNK))
        static let srvCopyChunkWrite = Command(rawValue: UInt32(SMB2_FSCTL_SRV_COPYCHUNK_WRITE))
        static let srvEnumerateSnapshots = Command(
            rawValue: UInt32(SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS))
        static let srvRequestResumeKey = Command(
            rawValue: UInt32(SMB2_FSCTL_SRV_REQUEST_RESUME_KEY))
        static let srvReadHash = Command(rawValue: UInt32(SMB2_FSCTL_SRV_READ_HASH))
        static let lmrRequestResilency = Command(
            rawValue: UInt32(SMB2_FSCTL_LMR_REQUEST_RESILIENCY))
        static let queryNetworkInterfaceInfo = Command(
            rawValue: UInt32(SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO))
        static let getReparsePoint = Command(rawValue: UInt32(SMB2_FSCTL_GET_REPARSE_POINT))
        static let setReparsePoint = Command(rawValue: UInt32(SMB2_FSCTL_SET_REPARSE_POINT))
        static let deleteReparsePoint = Command(rawValue: 0x0009_00AC)
        static let fileLevelTrim = Command(rawValue: UInt32(SMB2_FSCTL_FILE_LEVEL_TRIM))
        static let validateNegotiateInfo = Command(
            rawValue: UInt32(SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO))
    }

    struct SrvCopyChunk: IOCtlArgument {
        typealias Element = UInt8

        let sourceOffset: UInt64
        let targetOffset: UInt64
        let length: UInt32

        var regions: [Data] {
            return [
                .init(value: sourceOffset),
                .init(value: targetOffset),
                .init(value: length),
                .init(value: 0 as UInt32),
            ]
        }

        init(sourceOffset: UInt64, targetOffset: UInt64, length: UInt32) {
            self.sourceOffset = sourceOffset
            self.targetOffset = targetOffset
            self.length = length
        }
    }

    struct SrvCopyChunkCopy: IOCtlArgument {
        typealias Element = UInt8

        let sourceKey: Data
        let chunks: [SrvCopyChunk]

        var regions: [Data] {
            return [
                sourceKey,
                .init(value: UInt32(chunks.count)),
                .init(value: 0 as UInt32),
            ] + chunks.flatMap(\.regions)
        }

        init(sourceKey: Data, chunks: [SrvCopyChunk]) {
            self.sourceKey = sourceKey
            self.chunks = chunks
        }
    }

    struct RequestResumeKey: IOCtlReply {
        let resumeKey: Data

        init(data: Data) throws {
            guard data.count >= 24 else {
                throw POSIXError(.ENODATA)
            }
            self.resumeKey = data.prefix(24)
        }
    }

    struct SymbolicLinkReparse: IOCtlReply, IOCtlArgument {
        typealias Element = UInt8

        static private let headerLength = 20
        private let reparseTag: UInt32 = 0xA000_000C
        let substituteName: String
        let printName: String
        let isRelative: Bool

        init(data: Data) throws {
            guard data.scanValue(offset: 0, as: UInt32.self) == self.reparseTag else {
                throw POSIXError(.EINVAL)
            }
            let count = try data.scanInt(offset: 4, as: UInt16.self).unwrap()
            guard count + 8 == data.count else { throw POSIXError(.EINVAL) }

            let substituteOffset = try data.scanInt(offset: 8, as: UInt16.self).unwrap()
            let substituteLen = try data.scanInt(offset: 10, as: UInt16.self).unwrap()
            let printOffset = try data.scanInt(offset: 12, as: UInt16.self).unwrap()
            let printLen = try data.scanInt(offset: 14, as: UInt16.self).unwrap()
            let flag = try data.scanValue(offset: 16, as: UInt32.self).unwrap()

            let substituteData = data.dropFirst(
                Int(SymbolicLinkReparse.headerLength + substituteOffset)
            ).prefix(substituteLen)
            let printData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + printOffset))
                .prefix(printLen)
            let substituteName = try String(data: substituteData, encoding: .utf16LittleEndian)
                .unwrap()
            let printName = try String(data: printData, encoding: .utf16LittleEndian).unwrap()

            self.substituteName = substituteName
            self.printName = printName
            self.isRelative = flag & 1 == 1
        }

        var regions: [Data] {
            let substituteData = substituteName.data(using: .utf16LittleEndian)!
            let substituteLen = UInt16(substituteData.count)
            let printData = printName.data(using: .utf16LittleEndian)!
            let printLen = UInt16(printData.count)
            return [
                .init(value: reparseTag),
                .init(value: substituteLen + printLen),
                .init(value: 0 as UInt16),  // reserved
                .init(value: printLen),  // substitute offset
                .init(value: substituteLen),
                .init(value: 0 as UInt16),
                .init(value: printLen),
                .init(value: UInt32(isRelative ? 1 : 0)),
                .init(printData),
                .init(substituteData),
            ]
        }

        private init() {
            self.substituteName = ""
            self.printName = ""
            self.isRelative = false
        }
    }

    struct MountPointReparse: IOCtlReply, IOCtlArgument {
        typealias Element = UInt8

        static private let headerLength = 16
        private let reparseTag: UInt32 = 0xA000_0003
        let substituteName: String
        let printName: String

        init(data: Data) throws {
            guard data.scanValue(offset: 0, as: UInt32.self) == self.reparseTag else {
                throw POSIXError(.EINVAL)
            }

            let substituteOffset = try data.scanInt(offset: 8, as: UInt16.self).unwrap()
            let substituteLen = try data.scanInt(offset: 10, as: UInt16.self).unwrap()
            let printOffset = try data.scanInt(offset: 12, as: UInt16.self).unwrap()
            let printLen = try data.scanInt(offset: 14, as: UInt16.self).unwrap()

            let substituteData = data.dropFirst(
                Int(MountPointReparse.headerLength + substituteOffset)
            ).prefix(substituteLen)
            let printData = data.dropFirst(Int(MountPointReparse.headerLength + printOffset))
                .prefix(printLen)
            let substituteName = try String(data: substituteData, encoding: .utf16LittleEndian)
                .unwrap()
            let printName = try String(data: printData, encoding: .utf16LittleEndian).unwrap()

            self.substituteName = substituteName
            self.printName = printName
        }

        var regions: [Data] {
            let substituteData = substituteName.data(using: .utf16LittleEndian)!
            let substituteLen = UInt16(substituteData.count)
            let printData = printName.data(using: .utf16LittleEndian)!
            let printLen = UInt16(printData.count)
            return [
                .init(value: reparseTag),
                .init(value: substituteLen + printLen + 8),
                .init(value: 0 as UInt16),  // reserved
                .init(value: printLen),  // substitute offset
                .init(value: substituteLen),
                .init(value: 0 as UInt16),
                .init(value: printLen),
                .init(printData),
                .init(substituteData),
            ]
        }
    }
}
