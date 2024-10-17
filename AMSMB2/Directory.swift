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

typealias smb2dir = OpaquePointer

/// - Note: This class is NOT thread-safe.
final class SMB2Directory: Collection {
    private let context: SMB2Context
    private let handle: smb2dir

    init(_ path: String, on context: SMB2Context) throws {
        // Due to a unexpected free in closedir, async version is not usable.
        let handle = try context.withThreadSafeContext { context in
            smb2_opendir(context, path)
        }
        guard let handle = handle, unsafeBitCast(handle, to: UInt.self) & 0xffffff00 != 0 else {
            throw POSIXError(context.ntError.posixErrorCode, description: context.error)
        }
        
        self.handle = handle
        self.context = context
    }

    deinit {
        let handle = self.handle
        try? context.withThreadSafeContext { context in
            smb2_closedir(context, handle)
        }
    }

    func makeIterator() -> AnyIterator<smb2dirent> {
        let context = context.unsafeContext
        let handle = handle
        smb2_rewinddir(context, handle)
        return AnyIterator {
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
        let context = context.unsafeContext
        let handle = handle
        let currentPos = smb2_telldir(context, handle)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }

        smb2_rewinddir(context, handle)
        var i = 0
        while smb2_readdir(context, handle) != nil {
            i += 1
        }
        return i
    }

    subscript(_: Int) -> smb2dirent {
        let context = context.unsafeContext
        let handle = handle
        let currentPos = smb2_telldir(context, handle)
        smb2_seekdir(context, handle, 0)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }
        return smb2_readdir(context, handle).pointee
    }

    func index(after i: Int) -> Int {
        i + 1
    }
}
