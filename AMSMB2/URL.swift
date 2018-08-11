//
//  SMB2URL.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2

final class SMB2URL {
    private var _url: UnsafeMutablePointer<smb2_url>
    
    init(_ url: String, on context: SMB2Context) throws {
        _url = try context.withThreadSafeContext { (pcontext) in
            guard let result = smb2_parse_url(pcontext, url) else {
                throw SMB2URL.error(forDescription: context.error)
            }
            return result
        }
    }
    
    deinit {
        smb2_destroy_url(_url)
    }
    
    var domain: String? {
        guard let value = _url.pointee.domain else { return nil }
        return String.init(cString: value)
    }
    
    var path: String? {
        guard let value = _url.pointee.path else { return nil }
        return String.init(cString: value)
    }
    
    var server: String? {
        guard let value = _url.pointee.server else { return nil }
        return String.init(cString: value)
    }
    
    var share: String? {
        guard let value = _url.pointee.share else { return nil }
        return String.init(cString: value)
    }
    
    var user: String? {
        guard let value = _url.pointee.user else { return nil }
        return String.init(cString: value)
    }
}

extension SMB2URL {
    fileprivate static func error(forDescription errorDescription: String?) -> POSIXError {
        switch errorDescription {
        case "URL does not start with 'smb://'":
            return POSIXError(.ENOPROTOOPT, description: errorDescription)
        case "URL is too long":
            return POSIXError(.EOVERFLOW, description: errorDescription)
        case "Failed to allocate smb2_url":
            return POSIXError(.ENOMEM, description: errorDescription)
        default:
            return POSIXError(.EINVAL, description: errorDescription)
        }
    }
}
