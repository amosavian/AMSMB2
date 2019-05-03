//
//  fsctl.swift
//  AMSMB2
//
//  Created by Amir Abbas on 4/17/1397 AP.
//  Copyright © 1397 AP Mousavian. All rights reserved.
//

import Foundation
import SMB2

protocol DataInitializable {
    init(data: Data) throws
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
        static let srvEnumerateSnapshots = Command(rawValue: UInt32(SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS))
        static let srvRequestResumeKey = Command(rawValue: UInt32(SMB2_FSCTL_SRV_REQUEST_RESUME_KEY))
        static let srvReadHash = Command(rawValue: UInt32(SMB2_FSCTL_SRV_READ_HASH))
        static let lmrRequestResilency = Command(rawValue: UInt32(SMB2_FSCTL_LMR_REQUEST_RESILIENCY))
        static let queryNetworkInterfaceInfo = Command(rawValue: UInt32(SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO))
        static let setReparsePoint = Command(rawValue: UInt32(SMB2_FSCTL_SET_REPARSE_POINT))
        static let getReparsePoint = Command(rawValue: 0x000900A8)
        static let deleteReparsePoint = Command(rawValue: 0x000900AC)
        static let fileLevelTrim = Command(rawValue: UInt32(SMB2_FSCTL_FILE_LEVEL_TRIM))
        static let validateNegotiateInfo = Command(rawValue: UInt32(SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO))
        
        var maxResponseSize: Int {
            switch self {
            case .pipeWait, .lmrRequestResilency:
                return 0
            case .srvCopyChunk, .srvCopyChunkWrite:
                return 12
            case .srvRequestResumeKey:
                return 32
            case .queryNetworkInterfaceInfo:
                return 152
            default:
                return Int.max
            }
        }
    }
    
    struct SrvCopyChunk: DataProtocol {
        let sourceOffset: UInt64
        let targetOffset: UInt64
        let length: UInt32
        
        var regions: CollectionOfOne<Data> {
            var data = Data()
            data.append(value: sourceOffset)
            data.append(value: targetOffset)
            data.append(value: length)
            data.append(value: 0 as UInt32)
            return CollectionOfOne(data)
        }
        
        var startIndex: Int { return 0 }
        var endIndex: Int { return MemoryLayout.size(ofValue: self) }
        subscript(index: Int) -> UInt8 { get { return regions[0][index] } }
        func index(after i: Int) -> Int { return i + 1 }
    }
    
    struct SrvCopyChunkCopy: DataProtocol {
        let sourceKey: Data
        let chunks: [SrvCopyChunk]
        
        public var regions: CollectionOfOne<Data> {
            var data = Data()
            data.append(sourceKey)
            data.append(value: UInt32(chunks.count))
            data.append(value: 0 as UInt32)
            chunks.forEach { data.append($0.regions[0]) }
            return CollectionOfOne(data)
        }
        
        var startIndex: Int { return 0 }
        var endIndex: Int { return MemoryLayout.size(ofValue: self) }
        subscript(index: Int) -> UInt8 { get { return regions[0][index] } }
        func index(after i: Int) -> Int { return i + 1 }
    }
    
    struct RequestResumeKey: DataInitializable {
        let resumeKey: Data
        
        init(data: Data) throws {
            guard data.count >= 24 else {
                throw POSIXError(.ENODATA)
            }
            self.resumeKey = data.prefix(24)
        }
    }
    /*
    struct SymbolicLinkReparse: DataInitializable, DataProtocol {
        static private let headerLength = 16
        private let reparseTag: UInt32 = 0xA000000C
        let substituteName: String
        let printName: String
        let isRelative: Bool
        
        init(data: Data) throws {
            guard data.scanValue(offset: 0, as: UInt32.self) == self.reparseTag else {
                throw POSIXError(.EINVAL)
            }
            
            guard let substituteOffset = data.scanInt(offset: 8, as: UInt16.self),
                let substituteLen = data.scanInt(offset: 10, as: UInt16.self),
                let printOffset = data.scanInt(offset: 12, as: UInt16.self),
                let printLen = data.scanInt(offset: 14, as: UInt16.self),
                let flag = data.scanValue(offset: 16, as: UInt32.self) else {
                throw POSIXError(.EINVAL)
            }
            
            let substituteData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + substituteOffset)).prefix(substituteLen)
            let printData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + printOffset)).prefix(printLen)
            guard let substituteName = String(data: substituteData, encoding: .utf16LittleEndian),
                let printName = String(data: printData, encoding: .utf16LittleEndian) else {
                throw POSIXError(.EBADMSG)
            }
            
            self.substituteName = substituteName
            self.printName = printName
            self.isRelative = flag & 1 == 1
        }
        
        var regions: CollectionOfOne<Data> {
            let substituteData = substituteName.data(using: .utf16LittleEndian)!
            let substituteLen = UInt16(substituteData.count)
            let printData = printName.data(using: .utf16LittleEndian)!
            let printLen = UInt16(printData.count)
            var data = Data()
            data.append(value: reparseTag)
            data.append(value: substituteLen + printLen)
            data.append(value: 0 as UInt16) // reserved
            data.append(value: printLen) // substitute offset
            data.append(value: substituteLen)
            data.append(value: 0 as UInt16)
            data.append(value: printLen)
            data.append(value: UInt32(isRelative ? 1 : 0))
            data.append(printData)
            data.append(substituteData)
            return CollectionOfOne(data)
        }
        
        var startIndex: Int { return 0 }
        var endIndex: Int { return MemoryLayout.size(ofValue: self) }
        subscript(index: Int) -> UInt8 { get { return regions[0][index] } }
        func index(after i: Int) -> Int { return i + 1 }
    }
    
    struct MountPointReparse: DataInitializable, DataProtocol {
        static private let headerLength = 16
        private let reparseTag: UInt32 = 0xA0000003
        let substituteName: String
        let printName: String
        
        init(data: Data) throws {
            guard data.scanValue(offset: 0, as: UInt32.self) == self.reparseTag else {
                throw POSIXError(.EINVAL)
            }
            
            guard let substituteOffset = data.scanInt(offset: 8, as: UInt16.self),
                let substituteLen = data.scanInt(offset: 10, as: UInt16.self),
                let printOffset = data.scanInt(offset: 12, as: UInt16.self),
                let printLen = data.scanInt(offset: 14, as: UInt16.self) else {
                    throw POSIXError(.EINVAL)
            }
            
            let substituteData = data.dropFirst(Int(MountPointReparse.headerLength + substituteOffset)).prefix(substituteLen)
            let printData = data.dropFirst(Int(MountPointReparse.headerLength + printOffset)).prefix(printLen)
            guard let substituteName = String(data: substituteData, encoding: .utf16LittleEndian),
                let printName = String(data: printData, encoding: .utf16LittleEndian) else {
                    throw POSIXError(.EBADMSG)
            }
            
            self.substituteName = substituteName
            self.printName = printName
        }
        
        var regions: CollectionOfOne<Data> {
            let substituteData = substituteName.data(using: .utf16LittleEndian)!
            let substituteLen = UInt16(substituteData.count)
            let printData = printName.data(using: .utf16LittleEndian)!
            let printLen = UInt16(printData.count)
            var data = Data()
            data.append(value: reparseTag)
            data.append(value: substituteLen + printLen)
            data.append(value: 0 as UInt16) // reserved
            data.append(value: printLen) // substitute offset
            data.append(value: substituteLen)
            data.append(value: 0 as UInt16)
            data.append(value: printLen)
            data.append(printData)
            data.append(substituteData)
            return CollectionOfOne(data)
        }
        
        var startIndex: Int { return 0 }
        var endIndex: Int { return MemoryLayout.size(ofValue: self) }
        subscript(index: Int) -> UInt8 { get { return regions[0][index] } }
        func index(after i: Int) -> Int { return i + 1 }
    }*/
}
