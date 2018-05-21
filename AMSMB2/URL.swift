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
    
    init?(_ url: String, on context: SMB2Context) {
        _url = context.parseUrl(url)
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
