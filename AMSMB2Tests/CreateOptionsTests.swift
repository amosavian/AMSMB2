//
//  CreateOptionsTests.swift
//  AMSMB2
//
//  Locks in the constraint that `CreateOptions.init(flags:)` does not
//  emit `.noIntermediateBuffering` when `O_DIRECTORY` is also set.
//
//  Per MS-FSCC §2.1.5.1, FILE_NO_INTERMEDIATE_BUFFERING does not apply
//  to directories. Windows enforces this strictly: a CREATE that
//  carries both FILE_DIRECTORY_FILE and FILE_NO_INTERMEDIATE_BUFFERING
//  is rejected with STATUS_INVALID_PARAMETER (0xC000000D) before any
//  follow-up request (CHANGE_NOTIFY, etc.) ever runs.
//
//  Distributed under MIT license.
//

import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
@testable import AMSMB2

final class CreateOptionsTests: XCTestCase {

    func testO_SYNCAloneEmitsNoIntermediateBuffering() {
        let opts = SMB2FileHandle.CreateOptions(flags: O_RDONLY | O_SYNC)
        XCTAssertTrue(opts.contains(.noIntermediateBuffering),
                      "O_SYNC on a non-directory open should set .noIntermediateBuffering")
        XCTAssertFalse(opts.contains(.directoryFile))
    }

    func testO_DIRECTORYAloneSetsDirectoryFileWithoutBuffering() {
        let opts = SMB2FileHandle.CreateOptions(flags: O_RDONLY | O_DIRECTORY)
        XCTAssertTrue(opts.contains(.directoryFile))
        XCTAssertFalse(opts.contains(.noIntermediateBuffering))
    }

    func testO_SYNCWithO_DIRECTORYSuppressesNoIntermediateBuffering() {
        // The whole point of this fix: callers may pass O_RDONLY | O_SYNC
        // and then OR in O_DIRECTORY after a stat result; the resulting
        // CreateOptions must NOT include .noIntermediateBuffering or
        // Windows will reject the CREATE.
        let opts = SMB2FileHandle.CreateOptions(flags: O_RDONLY | O_SYNC | O_DIRECTORY)
        XCTAssertTrue(opts.contains(.directoryFile),
                      "O_DIRECTORY should still set .directoryFile")
        XCTAssertFalse(opts.contains(.noIntermediateBuffering),
                       "O_SYNC must not set .noIntermediateBuffering when O_DIRECTORY is also set (MS-FSCC §2.1.5.1)")
    }

    func testO_SYMLINKSetsOpenReparsePoint() {
        let opts = SMB2FileHandle.CreateOptions(flags: O_RDONLY | O_SYMLINK)
        XCTAssertTrue(opts.contains(.openReparsePoint))
        XCTAssertFalse(opts.contains(.directoryFile))
    }
}
