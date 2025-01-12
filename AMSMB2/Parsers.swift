//
//  Parsers.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/29/19.
//  Copyright © 2019 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2
import SMB2.Raw

struct EmptyReply: DecodableResponse {
    init(data _: Data) throws {}
    init(_: SMB2Client, _: UnsafeMutableRawPointer?) throws {}
}

extension String {
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try String(cString: dataPtr.unwrap().assumingMemoryBound(to: Int8.self))
    }
}

extension Array where Element == SMB2Share {
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        defer { smb2_free_data(client.context, dataPtr) }
        let result = try dataPtr.unwrap().assumingMemoryBound(to: srvsvc_NetrShareEnum_rep.self).pointee
        self = Array(result.ses.ShareInfo.Level1.Buffer.pointee)
    }

    init(_ ctr1: srvsvc_SHARE_INFO_1_carray) {
        self = [srvsvc_SHARE_INFO_1](
            UnsafeBufferPointer(start: ctr1.share_info_1, count: Int(ctr1.max_count))
        ).map {
            SMB2Share(
                name: .init(cString: $0.netname.utf8),
                props: .init(rawValue: $0.type),
                comment: .init(cString: $0.remark.utf8)
            )
        }
    }
}

extension Array where Element == SMB2FileChangeInfo {
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        var result = [SMB2FileChangeInfo]()
        dataPtr?.withMemoryRebound(to: smb2_file_notify_change_information.self, capacity: 1) { ptr in
            var ptr = ptr
            if ptr.pointee.name != nil {
                result.append(.init(ptr.pointee))
            }
            
            while ptr.pointee.next != nil {
                if ptr.pointee.name != nil {
                    result.append(.init(ptr.pointee))
                }
                ptr = ptr.pointee.next
            }
        }
        self = result
    }
}

extension OpaquePointer {
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try OpaquePointer(dataPtr.unwrap())
    }
}

struct SMB2FileID: RawRepresentable {
    let rawValue: smb2_file_id
    
    init?(rawValue: smb2_file_id) {
        self.rawValue = rawValue
    }
    
    init(_: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self.rawValue = try dataPtr.unwrap().assumingMemoryBound(to: smb2_create_reply.self).pointee
            .file_id
    }
}

extension DecodableResponse {
    init(_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_ioctl_reply.self).pointee
        guard reply.output_count > 0, let output = reply.output else {
            self = try Self(data: .init())
            return
        }
// Check memory validity in order to prevent crash on invalid pointers
#if canImport(Darwin)
        let pageSize = sysconf(_SC_PAGESIZE)
        let base = UnsafeMutableRawPointer(bitPattern: (size_t(bitPattern: output) / pageSize) * pageSize)
        if msync(base, pageSize, MS_ASYNC) != 0 {
            self = try Self(data: .init())
            return
        }
#endif
        defer { smb2_free_data(client.context, output) }
        let data = Data(bytes: output, count: Int(reply.output_count))
        self = try Self(data: data)
    }
}
