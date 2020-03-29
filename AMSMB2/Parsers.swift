//
//  Parsers.swift
//  AMSMB2
//
//  Created by Amir Abbas on 8/7/1398 AP.
//  Copyright © 1398 AP Mousavian. All rights reserved.
//

import Foundation
import SMB2

extension String {
    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try String(cString: dataPtr.unwrap().assumingMemoryBound(to: Int8.self))
    }
}

extension Array where Element == SMB2Share {
    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        defer { smb2_free_data(context.unsafe, dataPtr) }
        let result = try dataPtr.unwrap().assumingMemoryBound(to: srvsvc_netshareenumall_rep.self).pointee
        self = Array(result.ctr.pointee.ctr1)
    }
    
    init(_ ctr1: srvsvc_netsharectr1) {
        self = [srvsvc_netshareinfo1](UnsafeBufferPointer(start: ctr1.array, count: Int(ctr1.count))).map {
            SMB2Share(name: .init(cString: $0.name),
                      props: .init(rawValue: $0.type),
                      comment: .init(cString: $0.comment))
        }
    }
}

extension OpaquePointer {
    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        self = try OpaquePointer(dataPtr.unwrap())
    }
}

extension SMB2FileHandle {
    convenience init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let fileId = try dataPtr.unwrap().assumingMemoryBound(to: smb2_create_reply.self).pointee.file_id
        try self.init(fileDescriptor: fileId, on: context)
    }
}

extension DataInitializable {
    init(_ context: SMB2Context, _ dataPtr: UnsafeMutableRawPointer?) throws {
        let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_ioctl_reply.self).pointee
        guard reply.output_count > 0, let output = reply.output else {
            self = try Self.empty()
            return
        }
        defer { smb2_free_data(context.unsafe, output) }
        let data = Data(bytes: output, count: Int(reply.output_count))
        self = try Self(data: data)
    }
}
