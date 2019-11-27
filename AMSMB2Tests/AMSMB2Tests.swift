//
//  AMSMB2Tests.swift
//  AMSMB2Tests
//
//  Created by Amir Abbas on 2/27/1397 AP.
//  Copyright © 1397 AP Mousavian. All rights reserved.
//

import XCTest
@testable import AMSMB2

class AMSMB2Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        setenv("SMBServer", "smb://192.168.1.5/", 0)
        setenv("SMBShare", "Files", 0)
        setenv("SMBEncrypted", "0", 0)
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    @available(iOS 11.0, macOS 10.13, tvOS 11.0, *)
    func testNSCodable() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = AMSMB2(url: url, credential: credential)
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
        let decodedSMB = unarchiver.decodeObject(of: AMSMB2.self, forKey: NSKeyedArchiveRootObjectKey)
        XCTAssertNotNil(decodedSMB)
        XCTAssertEqual(smb?.url, decodedSMB?.url)
        XCTAssertEqual(smb?.timeout, decodedSMB?.timeout)
        XCTAssertNil(unarchiver.error)
    }
    
    func testCoding() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = AMSMB2(url: url, domain: "", credential: credential)
        XCTAssertNotNil(smb)
        do {
            let encoder = JSONEncoder()
            let json = try encoder.encode(smb!)
            XCTAssertFalse(json.isEmpty)
            let decoder = JSONDecoder()
            let decodedSMB = try decoder.decode(AMSMB2.self, from: json)
            XCTAssertEqual(smb!.url, decodedSMB.url)
            XCTAssertEqual(smb!.timeout, decodedSMB.timeout)
            
            let errorJson = String(data: json, encoding: .utf8)!.replacingOccurrences(of: "smb:", with: "smb2:").data(using: .utf8)!
            XCTAssertThrowsError(try decoder.decode(AMSMB2.self, from: errorJson))
        } catch {
            XCTAssert(false, error.localizedDescription)
        }
    }
    
    func testNSCopy() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = AMSMB2(url: url, domain: "", credential: credential)!
        let smbCopy = smb.copy() as! AMSMB2
        XCTAssertEqual(smb.url, smbCopy.url)
    }
    
    // Change server address and testing share
    lazy var server: URL = {
        return URL(string: ProcessInfo.processInfo.environment["SMBServer"]!)!
    }()
    lazy var share: String = {
        return ProcessInfo.processInfo.environment["SMBShare"]!
    }()
    lazy var credential: URLCredential? = {
        if let user = ProcessInfo.processInfo.environment["SMBUser"],
            let pass = ProcessInfo.processInfo.environment["SMBPassword"] {
            return URLCredential(user: user, password: pass, persistence: .forSession)
        } else {
            return nil
        }
    }()
    lazy var encrypted: Bool = {
        return ProcessInfo.processInfo.environment["SMBEncrypted"] == "1"
    }()
    
    func testConnectDisconnect() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.disconnectShare(gracefully: false) { (error) in
                XCTAssertNil(error)
                
                smb.connectShare(name: self.share, encrypted: self.encrypted) { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testShareEnum() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 3
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.listShares { result in
            var resultCount = 0
            switch result {
            case .success(let value):
                XCTAssertFalse(value.isEmpty)
                XCTAssert(value.contains(where: { $0.name == self.share }))
                resultCount = value.count
            case .failure(let error):
                XCTAssert(false, error.localizedDescription)
            }
            expectation.fulfill()
            
            smb.listShares(enumerateHidden: true) { result in
                switch result {
                case .success(let value):
                    XCTAssertFalse(value.isEmpty)
                    XCTAssert(value.contains(where: { $0.name == self.share }))
                    XCTAssertGreaterThanOrEqual(value.count, resultCount)
                case .failure(let error):
                    XCTAssert(false, error.localizedDescription)
                }
                expectation.fulfill()
            }
        }
        
        smb._swift_listShares { result in
            switch result {
            case .success(let value):
                XCTAssertFalse(value.isEmpty)
                XCTAssert(value.contains(where: { $0.name == self.share }))
            case .failure(let error):
                XCTAssert(false, error.localizedDescription)
            }
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testFileSystemAttributes() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.attributesOfFileSystem(forPath: "/") { result in
                switch result {
                case .success(let value):
                    XCTAssertFalse(value.isEmpty)
                    XCTAssertGreaterThanOrEqual(value[.systemSize] as! Int64, 0)
                    XCTAssertGreaterThanOrEqual(value[.systemFreeSize] as! Int64, 0)
                    XCTAssertGreaterThanOrEqual(value[.systemSize] as! Int64, value[.systemFreeSize] as! Int64)
                case .failure(let error):
                    XCTAssert(false, error.localizedDescription)
                }
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testListing() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.contentsOfDirectory(atPath: "/") { result in
                switch result {
                case .success(let value):
                    XCTAssertFalse(value.isEmpty)
                    XCTAssertNotNil(value.first)
                    guard let file = value.first else { break }
                    XCTAssertNotNil(file.name)
                    XCTAssertNotNil(file.contentModificationDate)
                    XCTAssertNotNil(file.creationDate)
                    XCTAssertGreaterThanOrEqual(file.contentModificationDate!, file.creationDate!)
                case .failure(let error):
                    XCTAssert(false, error.localizedDescription)
                }
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testSymlink() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.contentsOfDirectory(atPath: "/") { result in
                switch result {
                case .success(let value):
                    if let symlink = value.first(where: { $0.isSymbolicLink }) {
                        smb.destinationOfSymbolicLink(atPath: symlink.path!) { result in
                            switch result {
                            case .success(let value):
                                XCTAssert(!value.trimmingCharacters(in: CharacterSet.alphanumerics.inverted).isEmpty)
                            case .failure(let error):
                                XCTAssert(false, error.localizedDescription)
                            }
                            expectation.fulfill()
                        }
                    } else {
                        expectation.fulfill()
                    }
                case .failure(let error):
                    XCTAssert(false, error.localizedDescription)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testDirectoryOperation() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 5
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.timeout = 20
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.createDirectory(atPath: "testEmpty") { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.removeDirectory(atPath: "testEmpty", recursive: false) { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                }
            }
            
            smb.createDirectory(atPath: "testFull") { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.createDirectory(atPath: "testFull/test", completionHandler: { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                    
                    smb.removeDirectory(atPath: "testFull", recursive: true) { (error) in
                        XCTAssertNil(error)
                        expectation.fulfill()
                    }
                })
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testZeroWriteRead() {
        let size: Int = 0
        readWrite(size: size, function: #function)
    }
    
    func testSmallWriteRead() {
        let size: Int = random(max: 14)
        readWrite(size: size, function: #function)
    }
    
    private var optimizedSize = 1024 * 1024 // 1MB
    private var maxSize = 4 * 1024 * 1024 // 4MB
    
    func testMediumWriteRead() {
        let size: Int = 15 + random(max: optimizedSize - 15)
        readWrite(size: size, function: #function)
    }
    
    func testLargeWriteRead() {
        let size: Int = maxSize * 3 + random(max: optimizedSize)
        readWrite(size: size, checkLeak: true, function: #function)
    }
    
    private func readWrite(size: Int, checkLeak: Bool = false, function: String) {
        let expectation = self.expectation(description: function)
        expectation.expectedFulfillmentCount = 3
        
        let smb = AMSMB2(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)
        let baseMemUsage = report_memory()
        
        addTeardownBlock {
            smb.removeFile(atPath: "writetest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.write(data: data, toPath: "writetest.dat", progress: { (progress) -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(function, "uploaded:", progress, "of", size)
                return true
            }) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                if checkLeak {
                    XCTAssertLessThan(self.report_memory() - baseMemUsage, 2 * size)
                }
                
                smb.contents(atPath: "writetest.dat", progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertEqual(total, Int64(data.count))
                    print(function, "downloaded:", progress, "of", total)
                    return true
                }, completionHandler: { result in
                    if checkLeak {
                        XCTAssertLessThan(self.report_memory() - baseMemUsage, 2 * size)
                    }
                    switch result {
                    case .success(let rdata):
                        XCTAssertEqual(data, rdata)
                    case .failure(let error):
                        XCTAssert(false, error.localizedDescription)
                    }
                    expectation.fulfill()
                })
                
                smb.contents(atPath: "writetest.dat", range: ..<UInt64(10), progress: nil, completionHandler: { result in
                    if checkLeak {
                        XCTAssertLessThan(self.report_memory() - baseMemUsage, 2 * size)
                    }
                    switch result {
                    case .success(let rdata):
                        XCTAssertEqual(data.prefix(10), rdata)
                    case .failure(let error):
                        XCTAssert(false, error.localizedDescription)
                    }
                    expectation.fulfill()
                })
            }
        }
        
        wait(for: [expectation], timeout: 60)
        
        if checkLeak {
            print("\(function) after free memory usage:", self.report_memory() - baseMemUsage)
            XCTAssertLessThan(self.report_memory() - baseMemUsage, 2 * size)
        }
    }
    
    func testChunkedLoad() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        let file = "chunkedreadtest.dat"
        let size: Int = random(max: 0xF00000)
        let smb = AMSMB2(url: server, credential: credential)!
        print(#function, "test size:", size)
        let data = randomData(size: size)
        
        addTeardownBlock {
            smb.removeFile(atPath: file, completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.write(data: data, toPath: file, progress: nil) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                var cachedOffset: Int64 = 0
                smb.contents(atPath: file, fetchedData: { (offset, total, chunk) -> Bool in
                    XCTAssertEqual(offset, cachedOffset)
                    cachedOffset += Int64(chunk.count)
                    XCTAssertEqual(data[Int(offset)..<Int(cachedOffset)], chunk)
                    return true
                }) { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 60)
    }
    
    func testUploadDownload() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 3
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size: Int = random(max: 0xF00000)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")
        
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            smb.removeFile(atPath: "uploadtest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.uploadItem(at: url, toPath: "uploadtest.dat", progress: { (progress) -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.uploadItem(at: url, toPath: "uploadtest.dat", progress: nil) { (error) in
                    let error = error as? POSIXError
                    XCTAssertNotNil(error)
                    XCTAssertEqual(error?.code, POSIXErrorCode.EEXIST)
                    expectation.fulfill()
                }
                
                smb.downloadItem(atPath: "uploadtest.dat", to: dlURL, progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertGreaterThan(total, 0)
                    print(#function, "downloaded:", progress, "of", total)
                    return true
                }) { (error) in
                    XCTAssertNil(error)
                    XCTAssert(FileManager.default.contentsEqual(atPath: url.path, andPath: dlURL.path))
                    expectation.fulfill()
                }
            }
            
            smb.echo(completionHandler: nil)
            smb.disconnectShare(gracefully: true)
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testStreamUploadDownload() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        let file = "uploadtest.dat"
        let smb = AMSMB2(url: server, credential: credential)!
        let size: Int = random(max: 0xF00000)
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")
        let inputStream = InputStream(url: url)!
        let outputStream = OutputStream(url: dlURL, append: false)!
        
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            smb.removeFile(atPath: file, completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.write(stream: inputStream, toPath: file, progress: { (progress) -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }) { (error) in
                XCTAssertNil(error)
                XCTAssert(inputStream.streamStatus == .closed)
                expectation.fulfill()
                
                smb.downloadItem(atPath: file, to: outputStream, progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertGreaterThan(total, 0)
                    print(#function, "downloaded:", progress, "of", total)
                    return true
                }) { (error) in
                    XCTAssertNil(error)
                    XCTAssert(outputStream.streamStatus == .closed)
                    XCTAssert(FileManager.default.contentsEqual(atPath: url.path, andPath: dlURL.path))
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testTruncate() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size: Int = random(max: 0xF00000)
        let url = dummyFile(size: size)
        let file = "tructest.dat"
        
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            smb.removeFile(atPath: file, completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.uploadItem(at: url, toPath: file, progress: nil) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.truncateFile(atPath: file, atOffset: 0x10000) { error in
                    XCTAssertNil(error)
                    
                    smb.attributesOfItem(atPath: file) { result in
                        switch result {
                        case .success(let value):
                            XCTAssertEqual(value.fileSize, 0x10000)
                        case .failure(let error):
                            XCTAssert(false, error.localizedDescription)
                        }
                        
                        expectation.fulfill()
                    }
                }
            }
            
            smb.echo(completionHandler: nil)
            smb.disconnectShare(gracefully: true)
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testCopy() {
        let expectation = self.expectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size: Int = random(max: 0x400000)
        print(#function, "test size:", size)
        let data = randomData(size: size)
        
        addTeardownBlock {
            smb.removeFile(atPath: "copyTest.dat", completionHandler: nil)
            smb.removeFile(atPath: "copyTestDest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.write(data: data, toPath: "copyTest.dat", progress: nil) { (error) in
                XCTAssertNil(error)
                smb.copyItem(atPath: "copyTest.dat", toPath: "copyTestDest.dat", recursive: false, progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertEqual(total, Int64(data.count))
                    print(#function, "copied:", progress, "of", total)
                    return true
                }) { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                    
                    smb.attributesOfItem(atPath: "copyTestDest.dat", completionHandler: { result in
                        switch result {
                        case .success(let value):
                            XCTAssertEqual(value.fileSize, Int64(data.count))
                        case .failure(let error):
                            XCTAssert(false, error.localizedDescription)
                        }
                        expectation.fulfill()
                    })
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testMove() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        addTeardownBlock {
            smb.removeFile(atPath: "moveTest", completionHandler: nil)
            smb.removeFile(atPath: "moveTestDest", completionHandler: nil)
        }
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.createDirectory(atPath: "moveTest") { (error) in
                XCTAssertNil(error)
                
                smb.moveItem(atPath: "moveTest", toPath: "moveTestDest") { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testRecursiveCopyRemove() {
        let expectation = self.expectation(description: #function)
        
        let root = "recCopyTest"
        let rootCopy = "recCopyTest Copy"
        let smb = AMSMB2(url: server, credential: credential)!
        
        addTeardownBlock {
            smb.removeDirectory(atPath: root, recursive: true, completionHandler: nil)
            smb.removeDirectory(atPath: rootCopy, recursive: true, completionHandler: nil)
        }
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)

            smb.createDirectory(atPath: root) { (error) in
                XCTAssertNil(error)
                
                smb.createDirectory(atPath: "\(root)/subdir")  { (error) in
                    XCTAssertNil(error)
                    
                    smb.write(data: [0x01, 0x02, 0x03], toPath: "\(root)/file", progress: nil) { (error) in
                        XCTAssertNil(error)
                        
                        smb.copyItem(atPath: root, toPath: rootCopy, recursive: true, progress: nil) { (error) in
                            XCTAssertNil(error)
                            
                            smb.attributesOfItem(atPath: "\(rootCopy)/file") { result in
                                switch result {
                                case .success(let value):
                                    XCTAssertEqual(value.fileSize, 3)
                                case .failure(let error):
                                    XCTAssert(false, error.localizedDescription)
                                }
                                
                                expectation.fulfill()
                            }
                        }
                    }
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testRemove() {
        let expectation = self.expectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        
        smb.connectShare(name: share, encrypted: encrypted) { (error) in
            XCTAssertNil(error)
            
            smb.createDirectory(atPath: "removeTest") { (error) in
                XCTAssertNil(error)
                
                smb.createDirectory(atPath: "removeTest/subdir")  { (error) in
                    XCTAssertNil(error)
                    
                    smb.write(data: Data(), toPath: "removeTest/file", progress: nil) { (error) in
                        XCTAssertNil(error)
                        
                        smb.removeDirectory(atPath: "removeTest", recursive: true) { (error) in
                            XCTAssertNil(error)
                            expectation.fulfill()
                        }
                    }
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
}

extension AMSMB2Tests {
    fileprivate func random<T: FixedWidthInteger>(max: T) -> T {
        #if swift(>=4.2)
        return T.random(in: 0...max)
        #else
        return T(arc4random_uniform(Int32(max)))
        #endif
    }
    
    fileprivate func randomData(size: Int = 262144) -> Data {
        var keyBuffer = [UInt8](repeating: 0, count: size)
        let result = SecRandomCopyBytes(kSecRandomDefault, keyBuffer.count, &keyBuffer)
        if result == errSecSuccess {
            return Data(keyBuffer)
        } else {
            fatalError("Problem generating random bytes")
        }
    }
    
    fileprivate func dummyFile() -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dummyfile.dat")
        
        if !FileManager.default.fileExists(atPath: url.path) {
            let data = randomData()
            try! data.write(to: url)
        }
        return url
    }
    
    fileprivate func dummyFile(size: Int, name: String = #function) -> URL {
        let name = name.trimmingCharacters(in: CharacterSet(charactersIn: "()"))
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)
        
        if FileManager.default.fileExists(atPath: url.path) {
            try! FileManager.default.removeItem(at: url)
        }
        
        let data = randomData(size: size)
        try! data.write(to: url)
        return url
    }
    
    fileprivate func report_memory() -> Int {
        var taskInfo = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size)/4
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &taskInfo) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        
        if kerr == KERN_SUCCESS {
            return Int(taskInfo.resident_size)
        }
        else {
            return -1
        }
    }
}
