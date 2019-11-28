//
//  Parsers.swift
//  AMSMB2
//
//  Created by Amir Abbas on 8/7/1398 AP.
//  Copyright © 1398 AP Mousavian. All rights reserved.
//

import Foundation
import SMB2

struct Parser {
    static func toVoid(_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> Void {
        return ()
    }
    
    static func toString(_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> String {
        return try String(cString: dataPtr.unwrap().assumingMemoryBound(to: Int8.self))
    }
    
    static func toSMB2Shares(_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> [SMB2Share] {
        defer { smb2_free_data(context, dataPtr) }
        let result = try dataPtr.unwrap().assumingMemoryBound(to: srvsvc_netshareenumall_rep.self).pointee
        return .init(result.ctr.pointee.ctr1)
    }
    
    static func toOpaquePointer(_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> OpaquePointer {
        return try OpaquePointer(dataPtr.unwrap())
    }
    
    static func toFileId(_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> smb2_file_id {
        return try dataPtr.unwrap().assumingMemoryBound(to: smb2_create_reply.self).pointee.file_id
    }
    
    static func ioctlOutputConverter<R: DataInitializable>(as: R.Type) ->
        ((_ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?) throws -> R) {
            return { context, dataPtr in
                let reply = try dataPtr.unwrap().assumingMemoryBound(to: smb2_ioctl_reply.self).pointee
                guard reply.output_count > 0, let output = reply.output else {
                    return try .empty()
                }
                defer { smb2_free_data(context, output) }
                let data = Data(bytes: output, count: Int(reply.output_count))
                return try R(data: data)
            }
    }
}

extension Array where Element == SMB2Share {
    init(_ ctr1: srvsvc_netsharectr1) {
        self = [srvsvc_netshareinfo1](UnsafeBufferPointer(start: ctr1.array, count: Int(ctr1.count))).map {
            SMB2Share(name: .init(cString: $0.name),
                      props: .init(rawValue: $0.type),
                      comment: .init(cString: $0.comment))
        }
    }
}
