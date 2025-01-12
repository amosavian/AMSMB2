//
//  Directory.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

typealias smb2dirPointer = UnsafeMutablePointer<smb2dir>?

/// - Note: This class is NOT thread-safe.
final class SMB2Directory: Collection {
    private let path: String
    private let client: SMB2Client
    private var handle: smb2dirPointer

    init(_ path: String, on client: SMB2Client) throws {
        self.path = path
        let (_, handle) = try client.async_await(dataHandler: OpaquePointer.init) { context, cbPtr -> Int32 in
            smb2_opendir_async(context, path, SMB2Client.generic_handler, cbPtr)
        }
        
        self.client = client
        self.handle = .init(handle)
    }

    deinit {
        try? client.withThreadSafeContext { context in
            smb2_closedir(context, handle)
        }
    }
    
    func makeIterator() -> AnyIterator<smb2dirent> {
        let context = client.context
        smb2_rewinddir(context, handle)
        return AnyIterator { [handle] in
            smb2_readdir(context, handle)?.pointee
        }
    }

    var startIndex: Int {
        0
    }

    var endIndex: Int {
        count
    }

    var count: Int {
        let context = client.context
        let currentPos = smb2_telldir(context, handle)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }

        smb2_rewinddir(context, handle)
        var result = 0
        while smb2_readdir(context, handle) != nil {
            result += 1
        }
        return result
    }

    subscript(_: Int) -> smb2dirent {
        let context = client.context
        let currentPos = smb2_telldir(context, handle)
        smb2_seekdir(context, handle, 0)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }
        return smb2_readdir(context, handle).pointee
    }

    func index(after index: Int) -> Int {
        index + 1
    }
}
