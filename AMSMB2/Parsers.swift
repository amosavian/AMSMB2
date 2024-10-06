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

struct EmptyReply: IOCtlReply {
    init(data _: Data) throws {}
    init(_: SMB2Context, _: UnsafeMutableRawPointer?) throws {}
}

extension String {
    init(_: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try String(cString: dataPtr.unwrap().assumingMemoryBound(to: Int8.self))
    }
}

// extension Array where Element == SMB2Share {
//    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
//        defer { smb2_free_data(context.unsafe, dataPtr) }
//        let result = try dataPtr.unwrap().assumingMemoryBound(to: srvsvc_netshareenumall_rep.self)
//            .pointee
//        self = Array(result.ctr.pointee.ctr1)
//    }
//
//    init(_ ctr1: srvsvc_netsharectr1) {
//        self = [srvsvc_netshareinfo1](
//            UnsafeBufferPointer(start: ctr1.array, count: Int(ctr1.count))
//        ).map {
//            SMB2Share(
//                name: .init(cString: $0.name),
//                props: .init(rawValue: $0.type),
//                comment: .init(cString: $0.comment)
//            )
//        }
//    }
// }

extension OpaquePointer {
    init(_: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try OpaquePointer(dataPtr.unwrap())
    }
}

extension SMB2FileHandle {
    convenience init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let fileId = try dataPtr.unwrap().assumingMemoryBound(to: smb2_create_reply.self).pointee
            .file_id
        try self.init(fileDescriptor: fileId, on: context)
    }
}

extension IOCtlReply {
    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_ioctl_reply.self).pointee
        guard reply.output_count > 0, let output = reply.output else {
            self = try Self(data: .init())
            return
        }
        // Check memory validity in order to prevent crash on invalid pointers
        let pageSize = sysconf(_SC_PAGESIZE)
        let base = UnsafeMutableRawPointer(bitPattern: (size_t(bitPattern: output) / pageSize) * pageSize)
        if msync(base, pageSize, MS_ASYNC) != 0 {
            self = try Self(data: .init())
            return
        }
        defer { smb2_free_data(context.unsafe, output) }
        let data = Data(bytes: output, count: Int(reply.output_count))
        self = try Self(data: data)
    }
}
