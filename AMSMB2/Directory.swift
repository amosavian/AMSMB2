//
//  Directory.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation
import SMB2

typealias smb2dir = OpaquePointer

/// NO THREAD-SAFE
final class SMB2Directory: Collection {
    private var context: SMB2Context
    private var handle: smb2dir
    
    init(_ path: String, on context: SMB2Context) throws {
        let (_, handle) = try context.async_await(dataHandler: Parser.toOpaquePointer) { (context, cbPtr) -> Int32 in
            smb2_opendir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
        
        self.context = context
        self.handle = handle
    }
    
    deinit {
        let handle = self.handle
        try? context.withThreadSafeContext { (context) in
            smb2_closedir(context, handle)
        }
    }
    
    func makeIterator() -> AnyIterator<smb2dirent> {
        let context = self.context.context
        let handle = self.handle
        smb2_rewinddir(context, handle)
        return AnyIterator {
            return smb2_readdir(context, self.handle)?.pointee
        }
    }
    
    var startIndex: Int {
        return 0
    }
    
    var endIndex: Int {
        return count
    }
    
    var count: Int {
        let context = self.context.context
        let handle = self.handle
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
    
    subscript(position: Int) -> smb2dirent {
        let context = self.context.context
        let handle = self.handle
        let currentPos = smb2_telldir(context, handle)
        smb2_seekdir(context, handle, 0)
        defer {
            smb2_seekdir(context, handle, currentPos)
        }
        return smb2_readdir(context, handle).move()
    }
    
    func index(after i: Int) -> Int {
        return i + 1
    }
}
