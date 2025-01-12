//
//  SMB2ManagerTests.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import XCTest

import Atomics
#if canImport(Darwin)
@preconcurrency import Darwin
#else
import FoundationNetworking
#endif
@testable import AMSMB2

private func folderName(postfix: String = "", name: String = #function) -> String {
    "\(name.trimmingCharacters(in: .init(charactersIn: "()")))\(postfix)"
}

private func fileName(postfix: String = "", name: String = #function) -> String {
    "\(name.trimmingCharacters(in: .init(charactersIn: "()")))\(postfix).dat"
}

class SMB2ManagerTests: XCTestCase, @unchecked Sendable {
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    @available(iOS 11.0, macOS 10.13, tvOS 11.0, *)
    func testNSCodable() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, credential: credential)
        XCTAssertNotNil(smb)
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        archiver.encode(smb, forKey: NSKeyedArchiveRootObjectKey)
        archiver.finishEncoding()
        let data = archiver.encodedData
        XCTAssertNil(archiver.error)
        XCTAssertFalse(data.isEmpty)
        let unarchiver = try! NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver.decodingFailurePolicy = .setErrorAndReturn
        unarchiver.requiresSecureCoding = true
        let decodedSMB = unarchiver.decodeObject(
            of: SMB2Manager.self, forKey: NSKeyedArchiveRootObjectKey
        )
        XCTAssertNotNil(decodedSMB)
        XCTAssertEqual(smb?.url, decodedSMB?.url)
        XCTAssertEqual(smb?.timeout, decodedSMB?.timeout)
        XCTAssertNil(unarchiver.error)
    }

    func testCoding() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, domain: "", credential: credential)
        XCTAssertNotNil(smb)
        do {
            let encoder = JSONEncoder()
            let json = try encoder.encode(smb!)
            XCTAssertFalse(json.isEmpty)
            let decoder = JSONDecoder()
            let decodedSMB = try decoder.decode(SMB2Manager.self, from: json)
            XCTAssertEqual(smb!.url, decodedSMB.url)
            XCTAssertEqual(smb!.timeout, decodedSMB.timeout)

            let errorJson = String(data: json, encoding: .utf8)!.replacingOccurrences(
                of: "smb:", with: "smb2:"
            ).data(using: .utf8)!
            XCTAssertThrowsError(try decoder.decode(SMB2Manager.self, from: errorJson))
        } catch {
            XCTAssert(false, error.localizedDescription)
        }
    }

    func testNSCopy() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = SMB2Manager(url: url, domain: "", credential: credential)!
        let smbCopy = smb.copy() as! SMB2Manager
        XCTAssertEqual(smb.url, smbCopy.url)
    }

    // Change server address and testing share
    lazy var server: URL = .init(string: ProcessInfo.processInfo.environment["SMB_SERVER"]!)!

    lazy var share: String = ProcessInfo.processInfo.environment["SMB_SHARE"]!

    lazy var credential: URLCredential? = {
        if let user = ProcessInfo.processInfo.environment["SMB_USER"],
           let pass = ProcessInfo.processInfo.environment["SMB_PASSWORD"]
        {
            return URLCredential(user: user, password: pass, persistence: .forSession)
        } else {
            return nil
        }
    }()

    lazy var encrypted: Bool = ProcessInfo.processInfo.environment["SMB_ENCRYPTED"] == "1"

    func testConnectDisconnect() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.disconnectShare(gracefully: false)
        try await smb.connectShare(name: share, encrypted: encrypted)
    }

    func testShareEnum() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!

        let shares = try await smb.listShares()
        XCTAssertFalse(shares.isEmpty)
        XCTAssert(shares.contains(where: { $0.name == self.share }))

        let hiddenShares = try await smb.listShares(enumerateHidden: true)
        XCTAssertFalse(hiddenShares.isEmpty)
        XCTAssert(hiddenShares.contains(where: { $0.name == self.share }))
        XCTAssertGreaterThanOrEqual(hiddenShares.count, shares.count)

        let swiftShares = try await smb._swift_listShares()
        XCTAssertFalse(swiftShares.isEmpty)
        XCTAssert(swiftShares.contains(where: { $0.name == self.share }))
    }

    func testFileSystemAttributes() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        let fsAttributes = try await smb.attributesOfFileSystem(forPath: "/")
        XCTAssertFalse(fsAttributes.isEmpty)
        XCTAssertGreaterThanOrEqual(fsAttributes[.systemSize] as! Int64, 0)
        XCTAssertGreaterThanOrEqual(fsAttributes[.systemFreeSize] as! Int64, 0)
        XCTAssertGreaterThanOrEqual(
            fsAttributes[.systemSize] as! Int64, fsAttributes[.systemFreeSize] as! Int64
        )
    }
    
    func testFileAttributes() async throws {
        let file = fileName()
        let size: Int = random(max: 0x000800)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        let initialAttribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertNotNil(initialAttribs.name)
        XCTAssertNotNil(initialAttribs.contentModificationDate)
        XCTAssertNotNil(initialAttribs.creationDate)
        XCTAssertGreaterThanOrEqual(initialAttribs.contentModificationDate!, initialAttribs.creationDate!)
        XCTAssertEqual(initialAttribs[.isHiddenKey] as? Bool, nil)
        
        try await smb.setAttributes(attributes: [
            .creationDateKey: Date(timeIntervalSinceReferenceDate: 0),
            .isHiddenKey: true,
        ], ofItemAtPath: file)
        
        let newAttribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertEqual(initialAttribs.contentModificationDate, newAttribs.contentModificationDate)
        XCTAssertEqual(newAttribs.creationDate, Date(timeIntervalSinceReferenceDate: 0))
    }
    
    func testFileRename() async throws {
        let file = fileName()
        let renamedFile = fileName(postfix: "Renamed")
        let size: Int = random(max: 0x000800)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
            try? await smb.removeFile(atPath: renamedFile)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        try await smb.moveItem(atPath: file, toPath: renamedFile)
        let renamedData = try await smb.contents(atPath: renamedFile)
        XCTAssertEqual(data, renamedData)
    }
    
    func testFileTruncate() async throws {
        let file = fileName()
        let size: Int = random(min: 0x000401, max: 0x002000)
        let smb = SMB2Manager(url: server, credential: credential)!
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)
        
        try await smb.truncateFile(atPath: file, atOffset: UInt64(min(0x000200, size / 2)))
        let truncData = try await smb.contents(atPath: file)
        XCTAssertEqual(truncData.count, 0x000200)
        XCTAssertEqual(data.prefix(truncData.count), truncData)
    }
    
    func testListing() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        let contents = try await smb.contentsOfDirectory(atPath: "/")
        XCTAssertFalse(contents.isEmpty)
        XCTAssertNotNil(contents.first)
        guard let file = contents.first else { return }
        XCTAssertNotNil(file.name)
        XCTAssertNotNil(file.contentModificationDate)
        XCTAssertNotNil(file.creationDate)
        XCTAssertGreaterThanOrEqual(file.contentModificationDate!, file.creationDate!)
    }

    func testSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        let contents = try await smb.contentsOfDirectory(atPath: "/")
        if let symlink = contents.first(where: { $0.isSymbolicLink }) {
            let destination = try await smb.destinationOfSymbolicLink(atPath: symlink.path!)
            XCTAssert(
                !destination.trimmingCharacters(
                    in: CharacterSet.alphanumerics.inverted
                ).isEmpty
            )
        }
    }
    
    func testCreateSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let target = fileName(postfix: "Target")
        let link = fileName()
        let data = randomData(size: 0x000800)
        
        addTeardownBlock {
            try? await smb.removeFile(atPath: target)
            try? await smb.removeFile(atPath: link)
        }
        
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: target, progress: nil)
        try await smb.createSymbolicLink(atPath: link, withDestinationPath: target)
        
        let attribs = try await smb.attributesOfItem(atPath: link)
        XCTAssertNotNil(attribs.contentModificationDate)
        XCTAssertNotNil(attribs.creationDate)
        XCTAssert(attribs.isSymbolicLink)
        XCTAssertEqual(attribs.fileResourceType, URLFileResourceType.symbolicLink)
        
        let destination = try await smb.destinationOfSymbolicLink(atPath: link)
        XCTAssertEqual(destination, target)
    }
    
    func testRemoveSymlink() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let target = fileName(postfix: "Target")
        let link = fileName()
        let data = randomData(size: 0x000800)
        
        addTeardownBlock {
            try? await smb.removeFile(atPath: target)
            try? await smb.removeFile(atPath: link)
        }
        
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: target, progress: nil)
        try await smb.createSymbolicLink(atPath: link, withDestinationPath: target)
        try await smb.removeFile(atPath: link)
        
        do {
            _ = try await smb.destinationOfSymbolicLink(atPath: link)
            XCTAssert(false, "Destination should not exist")
        } catch {}
    }

    func testDirectoryOperation() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "testEmpty")
        try await smb.removeDirectory(atPath: "testEmpty", recursive: false)

        try await smb.createDirectory(atPath: "testFull")
        try await smb.createDirectory(atPath: "testFull/test")
        try await smb.removeDirectory(atPath: "testFull", recursive: true)
    }

    func testZeroWriteRead() async throws {
        let size = 0
        try await readWrite(size: size, function: #function)
    }

    func testSmallWriteRead() async throws {
        let size: Int = random(max: 14)
        try await readWrite(size: size, function: #function)
    }

    private var optimizedSize = 1024 * 1024 // 1MB
    private var maxSize = 4 * 1024 * 1024 // 4MB

    func testMediumWriteRead() async throws {
        let size = 15 + random(max: optimizedSize - 15)
        try await readWrite(size: size, function: #function)
    }

    func testLargeWriteRead() async throws {
        let size: Int = maxSize * 3 + random(max: optimizedSize)
        try await readWrite(size: size, checkLeak: false, function: #function)
    }

    private func readWrite(size: Int, checkLeak: Bool = false, function: String) async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)
        let baseMemUsage = report_memory()

        addTeardownBlock {
            try? await smb.removeFile(atPath: fileName(name: function))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(
            data: data, toPath: fileName(name: function),
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(function, "uploaded:", progress, "of", size)
                return true
            }
        )
        if checkLeak {
            XCTAssertLessThan(report_memory() - baseMemUsage, 2 * size)
        }

        let rdata = try await smb.contents(
            atPath: fileName(name: function),
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertEqual(total, Int64(data.count))
                print(function, "downloaded:", progress, "of", total)
                return true
            }
        )
        if checkLeak {
            XCTAssertLessThan(report_memory() - baseMemUsage, 3 * size)
        }
        XCTAssertEqual(data, rdata)

        let trdata = try await smb.contents(
            atPath: fileName(name: function), range: ..<UInt64(10), progress: nil
        )
        XCTAssertEqual(data.prefix(10), trdata)

        if checkLeak {
            print("\(function) after free memory usage:", report_memory() - baseMemUsage)
            XCTAssertLessThan(report_memory() - baseMemUsage, 3 * size)
        }
    }

    func testChunkedLoad() async throws {
        let file = fileName()
        let size: Int = random(max: 0xf00000)
        let smb = SMB2Manager(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: file, progress: nil)

        return try await withCheckedThrowingContinuation { continuation in
            let cachedOffset: ManagedAtomic<Int64> = .init(0)
            smb.contents(atPath: file) { offset, _, chunk in
                XCTAssertEqual(offset, cachedOffset.load(ordering: .relaxed))
                _ = cachedOffset.loadThenWrappingIncrement(by: Int64(chunk.count), ordering: .relaxed)
                XCTAssertEqual(data[Int(offset)..<Int(cachedOffset.load(ordering: .relaxed))], chunk)
                return true
            } completionHandler: { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    func testUploadDownload() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0xf00000)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            try? await smb.removeFile(atPath: fileName())
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.uploadItem(
            at: url, toPath: fileName(),
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }
        )
        do {
            try await smb.uploadItem(at: url, toPath: fileName(), progress: nil)
            XCTAssert(false, "Upload must fail.")
        } catch {
            let error = error as? POSIXError
            XCTAssertNotNil(error)
            XCTAssertEqual(error?.code, POSIXErrorCode.EEXIST)
        }

        try await smb.downloadItem(
            atPath: fileName(), to: dlURL,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertGreaterThan(total, 0)
                print(#function, "downloaded:", progress, "of", total)
                return true
            }
        )
        XCTAssert(FileManager.default.contentsEqual(atPath: url.path, andPath: dlURL.path))

        try await smb.echo()
    }

    func testStreamUploadDownload() async throws {
        let file = fileName()
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0xf00000)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")
        let inputStream = AsyncThrowingStream(url: url)

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            try? await smb.removeFile(atPath: file)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(
            stream: inputStream, toPath: file,
            progress: { progress -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }
        )
        
        try await smb.downloadItem(
            atPath: file, to: dlURL,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertGreaterThan(total, 0)
                print(#function, "downloaded:", progress, "of", total)
                return true
            }
        )
        XCTAssert(FileManager.default.contentsEqual(atPath: url.path, andPath: dlURL.path))
    }
    
    func testSimultaneousUpload() async throws {
        let redownload = false
        let fileNums = 5
        let files = (1...fileNums).map { fileName(postfix: "\($0)") }
        let urls = (1...fileNums).map {
            let size: Int = random(max: 0xf00000)
            print(#function, "test size \($0):", size)
            return self.dummyFile(size: size)
        }
        
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share, encrypted: encrypted)
        
        addTeardownBlock {
            try? urls.forEach(FileManager.default.removeItem(at:))
            try? urls
                .map { $0.appendingPathExtension("download") }
                .forEach(FileManager.default.removeItem(at:))
            await withTaskGroup(of: Void.self) { group in
                for file in files {
                    group.addTask {
                        try? await smb.removeFile(atPath: file)
                    }
                }
                await group.waitForAll()
            }
            for file in files {
                try? await smb.removeFile(atPath: file)
            }
        }
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (file, url) in zip(files, urls) {
                group.addTask {
                    try await smb.uploadItem(at: url, toPath: file, progress: nil)
                }
            }
            
            try await group.waitForAll()
        }
        
        guard redownload else { return }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (file, url) in zip(files, urls) {
                group.addTask {
                    try await smb.downloadItem(atPath: file, to: url.appendingPathExtension("download"), progress: nil)
                }
            }
            
            try await group.waitForAll()
        }
    }

    func testTruncate() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0xf00000)
        let url = dummyFile(size: size)
        let file = fileName()

        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? await smb.removeFile(atPath: file)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.uploadItem(at: url, toPath: file, progress: nil)
        try await smb.truncateFile(atPath: file, atOffset: 0x10000)
        let attribs = try await smb.attributesOfItem(atPath: file)
        XCTAssertEqual(attribs.fileSize, 0x10000)

        try await smb.echo()
    }

    func testCopy() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let size: Int = random(max: 0x400000)
        print(#function, "test size:", size)
        let data = randomData(size: size)

        addTeardownBlock {
            try? await smb.removeFile(atPath: fileName())
            try? await smb.removeFile(atPath: fileName(postfix: "Dest"))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.write(data: data, toPath: fileName(), progress: nil)
        try await smb.copyItem(
            atPath: fileName(), toPath: fileName(postfix: "Dest"), recursive: false,
            progress: { progress, total -> Bool in
                XCTAssertGreaterThan(progress, 0)
                XCTAssertEqual(total, Int64(data.count))
                print(#function, "copied:", progress, "of", total)
                return true
            }
        )
        let attribs = try await smb.attributesOfItem(atPath: fileName(postfix: "Dest"))
        XCTAssertEqual(attribs.fileSize, Int64(data.count))
    }

    func testMove() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        addTeardownBlock {
            try? await smb.removeFile(atPath: folderName())
            try? await smb.removeFile(atPath: folderName(postfix: "Dest"))
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: folderName())
        try await smb.moveItem(atPath: folderName(), toPath: folderName(postfix: "Dest"))
    }

    func testRecursiveCopyRemove() async throws {
        let root = folderName()
        let rootCopy = folderName(postfix: " Copy")
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: root, recursive: true)
            try? await smb.removeDirectory(atPath: rootCopy, recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: root)
        try await smb.createDirectory(atPath: "\(root)/subdir")
        try await smb.write(data: [0x01, 0x02, 0x03], toPath: "\(root)/file", progress: nil)
        try await smb.copyItem(atPath: root, toPath: rootCopy, recursive: true, progress: nil)
        let attribs = try await smb.attributesOfItem(atPath: "\(rootCopy)/file")
        XCTAssertEqual(attribs.fileSize, 3)
    }

    func testRemove() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: folderName(), recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "\(folderName())")
        try await smb.createDirectory(atPath: "\(folderName())/subdir")
        try await smb.write(data: Data(), toPath: "\(folderName())/file", progress: nil)
        try await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
    }
    
    func testMonitor() async throws {
        try XCTSkipIf(true)
        let smb = SMB2Manager(url: server, credential: credential)!

        addTeardownBlock {
            try? await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
        }

        try await smb.connectShare(name: share, encrypted: encrypted)
        try await smb.createDirectory(atPath: "\(folderName())")
        try await smb.createDirectory(atPath: "\(folderName())/subdir")
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                do {
                    let changes = try await smb.monitorItem(atPath: "\(folderName())", for: [.fileName, .recursive])
                    XCTAssert(!changes.isEmpty)
                    print(changes)
                } catch {
                    print(error)
                    throw error
                }
            }
            try await Task.sleep(for: .seconds(1))
            group.addTask {
                try await smb.write(data: Data(), toPath: "\(folderName())/file", progress: nil)
            }
            try await group.waitForAll()
        }
        try await smb.removeDirectory(atPath: "\(folderName())", recursive: true)
    }
}

extension SMB2ManagerTests {
    private func random<T: FixedWidthInteger>(min: T = 0, max: T) -> T {
        T.random(in: min...max)
    }

    private func randomData(size: Int = 262_144) -> Data {
        Data((0..<size).map { _ in UInt8.random(in: 0...UInt8.max) })
    }
    
    private func dummyFile(size: Int = 262_144, name: String = #function) -> URL {
        let name = fileName(name: name)
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)

        if FileManager.default.fileExists(atPath: url.path) {
            try! FileManager.default.removeItem(at: url)
        }

        let data = randomData(size: size)
        try! data.write(to: url)
        return url
    }
    
    private func report_memory() -> Int {
#if canImport(Darwin)
        var taskInfo = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &taskInfo) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }

        if kerr == KERN_SUCCESS {
            return Int(taskInfo.resident_size)
        } else {
            return -1
        }
#else
        return 0
#endif
    }
}
