//
//  Extensions.swift
//  AMSMB2
//
//  Created by Amir Abbas on 2/31/1397 AP.
//  Copyright © 1397 AP Mousavian. All rights reserved.
//

import Foundation

extension POSIXError {
    static func throwIfError(_ result: Int32, default: POSIXError.Code) throws {
        guard result < 0 else {
            return
        }
        
        let error: Error? = POSIXErrorCode(rawValue: abs(result)).map { POSIXError($0) }
        throw error ?? POSIXError(`default`)
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
