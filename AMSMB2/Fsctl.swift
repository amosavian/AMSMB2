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
    static func empty() throws -> Self
}

extension Data: DataInitializable {
    init(data: Data) throws {
        self = data
    }
    
    static func empty() throws -> Data {
        return .init()
    }
}

protocol FcntlDataProtocol: DataProtocol { }

extension FcntlDataProtocol {
    var startIndex: Int {
        return 0
    }
    
    var endIndex: Int {
        return regions.first!.endIndex as! Int
    }
    
    subscript(index: Int) -> UInt8 {
        get {
            let regionOne = regions.first!
            return regionOne[regionOne.index(regionOne.startIndex, offsetBy: index)]
        }
    }
    
    func index(after i: Int) -> Int {
        return i + 1
    }
    
    func withContiguousStorageIfAvailable<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) rethrows -> R? {
        return try (regions.first! as! Data).withContiguousStorageIfAvailable(body)
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
        static let srvEnumerateSnapshots = Command(rawValue: UInt32(SMB2_FSCTL_SRV_ENUMERATE_SNAPSHOTS))
        static let srvRequestResumeKey = Command(rawValue: UInt32(SMB2_FSCTL_SRV_REQUEST_RESUME_KEY))
        static let srvReadHash = Command(rawValue: UInt32(SMB2_FSCTL_SRV_READ_HASH))
        static let lmrRequestResilency = Command(rawValue: UInt32(SMB2_FSCTL_LMR_REQUEST_RESILIENCY))
        static let queryNetworkInterfaceInfo = Command(rawValue: UInt32(SMB2_FSCTL_QUERY_NETWORK_INTERFACE_INFO))
        static let getReparsePoint = Command(rawValue: UInt32(SMB2_FSCTL_GET_REPARSE_POINT))
        static let setReparsePoint = Command(rawValue: UInt32(SMB2_FSCTL_SET_REPARSE_POINT))
        static let deleteReparsePoint = Command(rawValue: 0x000900AC)
        static let fileLevelTrim = Command(rawValue: UInt32(SMB2_FSCTL_FILE_LEVEL_TRIM))
        static let validateNegotiateInfo = Command(rawValue: UInt32(SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO))
    }
    
    struct SrvCopyChunk: FcntlDataProtocol {
        
        typealias Element = UInt8
        
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
    }
    
    struct SrvCopyChunkCopy: FcntlDataProtocol {
        
        typealias Element = UInt8
        
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
    }
    
    struct RequestResumeKey: DataInitializable {
        let resumeKey: Data
        
        init(data: Data) throws {
            guard data.count >= 24 else {
                throw POSIXError(.ENODATA)
            }
            self.resumeKey = data.prefix(24)
        }
        
        static func empty() throws -> RequestResumeKey {
            throw POSIXError(.ENODATA, description: "Invalid Resume Key")
        }
    }
    /*
    struct SymbolicLinkReparse: DataInitializable, FcntlDataProtocol {
        static private let headerLength = 20
        private let reparseTag: UInt32 = 0xA000000C
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
            
            let substituteData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + substituteOffset)).prefix(substituteLen)
            let printData = data.dropFirst(Int(SymbolicLinkReparse.headerLength + printOffset)).prefix(printLen)
            let substituteName = try String(data: substituteData, encoding: .utf16LittleEndian).unwrap()
            let printName = try String(data: printData, encoding: .utf16LittleEndian).unwrap()
            
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
        
        private init() {
            self.substituteName = ""
            self.printName = ""
            self.isRelative = false
        }
        
        static func empty() throws -> SymbolicLinkReparse {
            throw POSIXError(.ENODATA, description: "Invalid Reparse Point")
        }
    }
    
    struct MountPointReparse: DataInitializable, FcntlDataProtocol {
        static private let headerLength = 16
        private let reparseTag: UInt32 = 0xA0000003
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
            
            let substituteData = data.dropFirst(Int(MountPointReparse.headerLength + substituteOffset)).prefix(substituteLen)
            let printData = data.dropFirst(Int(MountPointReparse.headerLength + printOffset)).prefix(printLen)
            let substituteName = try String(data: substituteData, encoding: .utf16LittleEndian).unwrap()
            let printName = try String(data: printData, encoding: .utf16LittleEndian).unwrap()
            
            self.substituteName = substituteName
            self.printName = printName
        }
        
        static func empty() throws -> IOCtl.MountPointReparse {
            throw POSIXError(.ENODATA, description: "Invalid Reparse Point")
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
    }*/
}
