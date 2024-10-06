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
    private var context: SMB2Context
    private var handle: smb2dir

    init(_ path: String, on context: SMB2Context) throws {
        let (_, handle) = try context.async_await(dataHandler: OpaquePointer.init) {
            context, cbPtr -> Int32 in
            smb2_opendir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }

        self.context = context
        self.handle = handle
    }

    deinit {
        let handle = self.handle
        try? context.withThreadSafeContext { context in
            smb2_closedir(context, handle)
        }
    }

    func makeIterator() -> AnyIterator<smb2dirent> {
        let context = context.unsafe
        let handle = handle
        smb2_rewinddir(context, handle)
        return AnyIterator {
            smb2_readdir(context, self.handle)?.pointee
        }
    }

    var startIndex: Int {
        0
    }

    var endIndex: Int {
        count
    }

    var count: Int {
        let context = context.unsafe
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
        let context = context.unsafe
        let handle = handle
        let currentPos = smb2_telldir(context, handle)
        smb2_seekdir(context, handle, 0)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }
        return smb2_readdir(context, handle).move()
    }

    func index(after i: Int) -> Int {
        i + 1
    }
}
