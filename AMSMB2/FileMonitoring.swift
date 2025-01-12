//
//  FileMonitoring.swift
//  AMSMB2
//
//  Created by Amir Abbas on 10/14/24.
//  Copyright © 2024 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2

/// Change notifcation filter.
public struct SMB2FileChangeType: OptionSet, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt32
    
    var completionFilter: UInt32 {
        rawValue & 0x00ff_ffff
    }
    
    public var description: String {
        var result: [String] = []
        if contains(.fileName) { result.append("File Name") }
        if contains(.directoryName) { result.append("Directory Name") }
        if contains(.attributes) { result.append("Attributes") }
        if contains(.size) { result.append("Size") }
        if contains(.write) { result.append("Write Time") }
        if contains(.access) { result.append("Access Time") }
        if contains(.create) { result.append("Creation Time") }
        if contains(.extendedAttributes) { result.append("Extended Attributes") }
        if contains(.security) { result.append("Security") }
        if contains(.streamName) { result.append("Stream Name") }
        if contains(.streamSize) { result.append("Stream Size") }
        if contains(.streamWrite) { result.append("Stream Write") }
        if contains(.recursive) { result.append("Watch Tree") }
        return result.joined(separator: ", ")
    }
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    @_disfavoredOverload
    public init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    /// The client is notified if a file-name changes.
    public static let fileName: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME)
    
    /// The client is notified if a directory name changes.
    public static let directoryName: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_DIR_NAME)
    
    /// The client is notified if a file's attributes change.
    public static let attributes: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_ATTRIBUTES)
    
    /// The client is notified if a file's size changes.
    public static let size: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SIZE)
    
    /// The client is notified if the last write time of a file changes.
    public static let write: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_WRITE)
    
    /// The client is notified if the last access time of a file changes.
    public static let access: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_LAST_ACCESS)
    
    /// The client is notified if the creation time of a file changes.
    public static let create: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_CREATION)
    
    /// The client is notified if a file's extended attributes (EAs) change.
    public static let extendedAttributes: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_EA)
    
    /// The client is notified of a file's access control list (ACL) settings change.
    public static let security: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_SECURITY)
    
    /// The client is notified if a named stream is added to a file.
    public static let streamName: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_NAME)
    
    /// The client is notified if the size of a named stream is changed.
    public static let streamSize: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_SIZE)
    
    /// The client is notified if a named stream is modified.
    public static let streamWrite: Self = .init(rawValue: SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_STREAM_WRITE)
    
    /// The client is notified if a directory is added or removed within the watch tree.
    public static let recursive: Self = .init(rawValue: 0x8000_0000)
    
    /// The client is notified if last write time, creation time or size of a file modified.
    public static let contentModify: Self = [.create, .write, .size]
    
    /// The client is notified if any thing is changed.
    public static let all: Self = .init(rawValue: 0x0000_0fff)
}

/// The changes that occurred on the file.
public struct SMB2FileChangeAction: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    public var description: String {
        switch self {
        case .added: "Added"
        case .removed: "Removed"
        case .modified: "Modified"
        case .renamedOldName: "Rename with Old name"
        case .renamedNewName: "Rename with New name"
        case .addedStream: "Added Stream"
        case .removedStream: "Removed Stream"
        case .modifiedStream: "Modified Stream"
        default: "Unknown Action"
        }
    }
    
    @_disfavoredOverload
    public init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    /// The file was renamed, and FileName contains the new name.
    ///
    /// This notification is only sent when the rename operation changes the directory the file resides in.
    /// The client will also receive a `removed` notification.
    /// This notification will not be received if the file is renamed within a directory.
    public static let added = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED)
    
    /// The file was renamed, and FileName contains the old name.
    ///
    /// This notification is only sent when the rename operation changes the directory the file resides in.
    /// The client will also receive a `added` notification.
    /// This notification will not be received if the file is renamed within a directory.
    public static let removed = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED)
    
    /// The file was modified. This can be a change to the data or attributes of the file.
    public static let modified = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED)
    
    /// The file was renamed, and FileName contains the old name.
    ///
    /// This notification is only sent when the rename operation does not change the directory the file resides in.
    /// The client will also receive a `renamedNewName` notification.
    /// This notification will not be received if the file is renamed to a different directory.
    public static let renamedOldName = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_OLD_NAME)
    
    /// The file was renamed, and FileName contains the new name. This notification is only sent when the rename operation does not
    /// change the directory the file resides in. The client will also receive a FILE_ACTION_RENAMED_OLD_NAME notification. This
    /// notification will not be received if the file is renamed to a different directory.
    public static let renamedNewName = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_RENAMED_NEW_NAME)
    
    /// The file was added to a named stream.
    public static let addedStream = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_ADDED_STREAM)
    
    /// The file was removed from the named stream.
    public static let removedStream = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_REMOVED_STREAM)
    
    /// The file was modified. This can be a change to the data or attributes of the file.
    public static let modifiedStream = Self(rawValue: SMB2_NOTIFY_CHANGE_FILE_ACTION_MODIFIED_STREAM)
}

/// Structure contains the changes for which the client is being notified.
public struct SMB2FileChangeInfo: Hashable, Sendable {
    /// The changes that occurred on the file.
    public let action: SMB2FileChangeAction
    
    /// The name of the file that changed.
    public let fileName: String?
    
    init(action: SMB2FileChangeAction, fileName: String?) {
        self.action = action
        self.fileName = fileName
    }
    
    init(_ info: smb2_file_notify_change_information) {
        self.init(action: .init(rawValue: info.action), fileName: info.name.map(String.init(cString:)))
    }
}
