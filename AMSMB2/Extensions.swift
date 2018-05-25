//
//  Extensions.swift
//  AMSMB2
//
//  Created by Amir Abbas on 2/31/1397 AP.
//  Copyright © 1397 AP Mousavian. All rights reserved.
//

import Foundation

extension POSIXError {
    static func throwIfError(_ result: Int32, description: String?, default: POSIXError.Code) throws {
        guard result < 0 else {
            return
        }
        if let description = description, !description.isEmpty {
            let error: Error? = POSIXErrorCode(rawValue: abs(result)).map { POSIXError($0, userInfo: [NSLocalizedDescriptionKey: description]) }
            throw error ?? POSIXError(`default`, userInfo: [NSLocalizedDescriptionKey: description])
        } else {
            let error: Error? = POSIXErrorCode(rawValue: abs(result)).map { POSIXError($0) }
            throw error ?? POSIXError(`default`)
        }
    }
}


extension Dictionary where Key == URLResourceKey {
    var filename: String? {
        return self[.nameKey] as? String
    }
    
    var filepath: String? {
        return self[.pathKey] as? String
    }
    
    var filetype: URLFileResourceType? {
        return self[.fileResourceTypeKey] as? URLFileResourceType
    }
    
    var filesize: Int64? {
        return self[.fileSizeKey] as? Int64
    }
}

extension Data {
    mutating func append(uint16 value: UInt16) {
        self.append(contentsOf: [UInt8(value & 0xff), UInt8(value >> 8 & 0xff)])
    }
    
    mutating func append(uint32 value: UInt32) {
        self.append(contentsOf: [UInt8(value & 0xff), UInt8(value >> 8 & 0xff), UInt8(value >> 16 & 0xff), UInt8(value >> 24 & 0xff)])
    }
    
    mutating func append(uuid: UUID) {
        self.append(contentsOf: [uuid.uuid.3,  uuid.uuid.2,  uuid.uuid.1,  uuid.uuid.0,
                             uuid.uuid.5,  uuid.uuid.4,  uuid.uuid.7,  uuid.uuid.6,
                             uuid.uuid.8,  uuid.uuid.9,  uuid.uuid.10, uuid.uuid.11,
                             uuid.uuid.12, uuid.uuid.13, uuid.uuid.14, uuid.uuid.15])
    }
    
    func scanValue<T: FixedWidthInteger>(start: Int) -> T? {
        let length = MemoryLayout<T>.size
        guard self.count >= start + length else { return nil }
        var result: T = 0
        (self as NSData).getBytes(&result, range: NSRange(location: start, length: length))
        return result
    }
}
