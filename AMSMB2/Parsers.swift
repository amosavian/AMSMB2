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
    static func toString(_ context: UnsafeMutablePointer<smb2_context>?, _ dataPtr: UnsafeMutableRawPointer?) throws -> String {
        guard let resultPtr = dataPtr?.assumingMemoryBound(to: Int8.self) else {
             throw POSIXError(.ENOENT)
         }
        return String(cString: resultPtr)
    }
    
    static func toSMB2Shares(_ context: UnsafeMutablePointer<smb2_context>?, _ dataPtr: UnsafeMutableRawPointer?) throws -> [SMB2Share] {
        guard let dataPtr = dataPtr else {
            throw POSIXError(.ENOENT)
        }
        defer { smb2_free_data(context, dataPtr) }
        let result = dataPtr.load(as: srvsvc_netshareenumall_rep.self)
        return .init(result.ctr.pointee.ctr1)
    }
    
    static func toOpaquePointer(_ context: UnsafeMutablePointer<smb2_context>?, _ dataPtr: UnsafeMutableRawPointer?) throws -> OpaquePointer {
        guard let dataPtr = dataPtr else {
            throw POSIXError.init(POSIXErrorCode.EFAULT, description: "Handle is not valid.")
        }
        return OpaquePointer(dataPtr)
    }
    
    static func toFileId(_ context: UnsafeMutablePointer<smb2_context>?, _ dataPtr: UnsafeMutableRawPointer?) throws -> smb2_file_id {
        guard let reply = dataPtr?.bindMemory(to: smb2_create_reply.self, capacity: 1).pointee else {
            throw POSIXError(.EIO)
        }
        return reply.file_id
    }
    
    static func ioctlOutputConverter<R: DataInitializable>(as: R.Type) ->
        ((_ context: UnsafeMutablePointer<smb2_context>?, _ dataPtr: UnsafeMutableRawPointer?) throws -> R) {
            return { context, dataPtr in
                guard let reply = dataPtr?.bindMemory(to: smb2_ioctl_reply.self, capacity: 1).pointee else {
                    throw POSIXError(.EBADMSG, description: "Bad reply from ioctl command.")
                }
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
        var result = [SMB2Share]()
        let array = Array<srvsvc_netshareinfo1>(UnsafeBufferPointer(start: ctr1.array, count: Int(ctr1.count)))
        for item in array {
            let name = String(cString: item.name)
            let type = ShareProperties(rawValue: item.type)
            let comment = String(cString: item.comment)
            result.append(.init(name: name, props: type, comment: comment))
        }
        self = result
    }
}
