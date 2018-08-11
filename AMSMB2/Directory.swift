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
    
    typealias Index = Int
    
    private var context: SMB2Context
    private var handle: smb2dir
    
    init(_ path: String, on context: SMB2Context) throws {
        let (_, cmddata) = try context.async_await(defaultError: .ENOENT) { (context, cbPtr) -> Int32 in
            smb2_opendir_async(context, path, SMB2Context.generic_handler, cbPtr)
        }
        
        guard let handle = OpaquePointer(cmddata) else {
            throw POSIXError(.ENOTDIR)
        }
        
        self.context = context
        self.handle = handle
    }
    
    deinit {
        try? context.withThreadSafeContext { (context) in
            smb2_closedir(context, handle)
        }
    }
    
    func makeIterator() -> AnyIterator<smb2dirent> {
        smb2_rewinddir(context.context, handle)
        return AnyIterator {
            return smb2_readdir(self.context.context, self.handle)?.move()
        }
    }
    
    var startIndex: Int {
        return 0
    }
    
    var endIndex: Int {
        return self.count
    }
    
    var count: Int {
        let currentPos = smb2_telldir(context.context, handle)
        defer {
            smb2_seekdir(context.context, handle, currentPos)
        }
        
        smb2_rewinddir(context.context, handle)
        var i = 0
        while smb2_readdir(context.context, handle) != nil {
            i += 1
        }
        return i
    }
    
    subscript(position: Int) -> smb2dirent {
        let currentPos = smb2_telldir(context.context, handle)
        smb2_seekdir(context.context, handle, 0)
        defer {
            smb2_seekdir(context.context, handle, currentPos)
        }
        return smb2_readdir(context.context, handle).move()
    }
    
    func index(after i: Int) -> Int {
        return i + 1
    }
}
