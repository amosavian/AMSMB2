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
    private let path: String
    private let client: SMB2Client
    private var handle: smb2dir

    init(_ path: String, on client: SMB2Client) throws {
        self.path = path
        self.handle = try Self.openHandle(path, on: client)
        self.client = client
    }

    deinit {
        let handle = self.handle
        guard unsafeBitCast(handle, to: UInt.self) & 0xffff_f000 > 0 else {
            return
        }
        try? client.withThreadSafeContext { context in
            smb2_closedir(context, handle)
        }
    }
    
    static func openHandle(_ path: String, on client: SMB2Client) throws -> smb2dir {
        // Due to a unexpected free in closedir, async version is not usable.
        let handle = try client.withThreadSafeContext { context in
            smb2_opendir(context, path)
        }
        guard let handle else {
            throw POSIXError(client.ntError.posixErrorCode, description: client.error)
        }
        
        return handle
    }
    
    func safeHandle() -> smb2dir? {
        var handle = handle
        while unsafeBitCast(handle, to: UInt.self) & 0xffff_f000 == 0 {
            do {
                handle = try Self.openHandle(path, on: client)
                self.handle = handle
            } catch {
                return nil
            }
        }
        return handle
    }

    func makeIterator() -> AnyIterator<smb2dirent> {
        let context = client.context
        let handle = safeHandle()
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
        let context = client.context
        let handle = safeHandle()
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
        let handle = safeHandle()
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
