//
//  FileMonitoring.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/14/24.
//  Copyright © 2024 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import SMB2

/// Change notifcation filter.
struct SMB2FileChangeType: OptionSet, Sendable {
    public var rawValue: UInt32
    
    var completionFilter: UInt32 {
        rawValue & 0x00ff_ffff
    }
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    @_disfavoredOverload
    public init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    /// The client is notified if a file-name changes.
    public static let fileName: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_FILE_NAME)
    
    /// The client is notified if a directory name changes.
    public static let directoryName: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_DIR_NAME)
    
    /// The client is notified if a file's attributes change.
    public static let attributes: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_ATTRIBUTES)
    
    /// The client is notified if a file's size changes.
    public static let size: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_SIZE)
    
    /// The client is notified if the last write time of a file changes.
    public static let write: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_LAST_WRITE)
    
    /// The client is notified if the last access time of a file changes.
    public static let access: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_LAST_ACCESS)
    
    /// The client is notified if the creation time of a file changes.
    public static let create: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_CREATION)
    
    /// The client is notified if a file's extended attributes (EAs) change.
    public static let extendedAttributes: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_EA)
    
    /// The client is notified of a file's access control list (ACL) settings change.
    static let security: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_SECURITY)
    
    /// The client is notified if a named stream is added to a file.
    static let streamName: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_STREAM_NAME)
    
    /// The client is notified if the size of a named stream is changed.
    static let streamSize: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_STREAM_SIZE)
    
    /// The client is notified if a named stream is modified.
    static let streamWrite: Self = .init(rawValue: SMB2_CHANGE_NOTIIFY_FILE_NOTIFY_CHANGE_STREAM_WRITE)
    
    public static let recursive: Self = .init(rawValue: 0x8000_0000)
    
    /// The client is notified if last write time, creation time or size of a file modified.
    public static let contentModify: Self = [.create, .write, .size]
}
