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
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    @available(iOS 10.0, macOS 10.12, tvOS 10.0, *)
    func testNSCodable() {
        let url = URL(string: "smb://192.168.1.1/share")!
        let credential = URLCredential(user: "user", password: "password", persistence: .forSession)
        let smb = AMSMB2(url: url, domain: "", credential: credential)
        XCTAssertNotNil(smb)
        let archiver = NSKeyedArchiver()
        archiver.requiresSecureCoding = true
        archiver.encode(smb, forKey: "smb")
        archiver.finishEncoding()
        let data = archiver.encodedData
        XCTAssertNil(archiver.error)
        XCTAssertFalse(data.isEmpty)
        let unarchiver = NSKeyedUnarchiver(forReadingWith: data)
        unarchiver.decodingFailurePolicy = .setErrorAndReturn
        unarchiver.requiresSecureCoding = true
        let decodedSMB = unarchiver.decodeObject(of: AMSMB2.self, forKey: "smb")
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
        } catch {
            XCTAssert(false, error.localizedDescription)
        }
    }
    
    // Change server address and testing share
    let server = URL(string: "smb://192.168.1.5/")!
    let share = "Files"
    let credential: URLCredential? = nil
    
    func testShareEnum() {
        let expectation = XCTestExpectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.listShares { (name, comments, error) in
            XCTAssertNil(error)
            XCTAssertFalse(name.isEmpty)
            XCTAssertFalse(comments.isEmpty)
            XCTAssert(name.contains(self.share))
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testListing() {
        let expectation = XCTestExpectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share) { (error) in
            XCTAssertNil(error)
            
            smb.contentOfDirectory(atPath: "/") { (files, error) in
                XCTAssertNil(error)
                XCTAssertFalse(files.isEmpty)
                XCTAssertNotNil(files.first?.filename)
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testDirectoryOperation() {
        let expectation = XCTestExpectation(description: #function)
        expectation.expectedFulfillmentCount = 5
        
        let smb = AMSMB2(url: server, credential: credential)!
        smb.connectShare(name: share) { (error) in
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
    
    func testWriteRead() {
        let expectation = XCTestExpectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size = Int(arc4random_uniform(0xF00000))
        print(#function, "test size:", size)
        let data = randomData(size: size)
        
        addTeardownBlock {
            smb.removeFile(atPath: "writetest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share) { (error) in
            XCTAssertNil(error)
            
            smb.write(data: data, toPath: "writetest.dat", progress: { (progress) -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.contents(atPath: "writetest.dat", progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertEqual(total, Int64(data.count))
                    print(#function, "downloaded:", progress, "of", total)
                    return true
                }, completionHandler: { (rdata, error) in
                    XCTAssertNil(error)
                    XCTAssertEqual(data, rdata)
                    expectation.fulfill()
                })
            }
        }
        
        wait(for: [expectation], timeout: 60)
    }
    
    func testUploadDownload() {
        let expectation = XCTestExpectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size = Int(arc4random_uniform(0xF00000))
        print(#function, "test size:", size)
        let url = dummyFile(size: size)
        let dlURL = url.appendingPathExtension("downloaded")
        
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: dlURL)
            smb.removeFile(atPath: "uploadtest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share) { (error) in
            XCTAssertNil(error)
            
            smb.uploadItem(at: url, toPath: "uploadtest.dat", progress: { (progress) -> Bool in
                XCTAssertGreaterThan(progress, 0)
                print(#function, "uploaded:", progress, "of", size)
                return true
            }) { (error) in
                XCTAssertNil(error)
                expectation.fulfill()
                
                smb.downloadItem(atPath: "uploadtest.dat", to: dlURL, progress: { (progress, total) -> Bool in
                    XCTAssertGreaterThan(progress, 0)
                    XCTAssertGreaterThan(total, 0)
                    print(#function, "downloaded:", progress, "of", total)
                    return true
                }) { (error) in
                    XCTAssertNil(error)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testCopy() {
        let expectation = XCTestExpectation(description: #function)
        expectation.expectedFulfillmentCount = 2
        
        
        let smb = AMSMB2(url: server, credential: credential)!
        let size = Int(arc4random_uniform(0x400000))
        print(#function, "test size:", size)
        let data = randomData(size: size)
        
        addTeardownBlock {
            smb.removeFile(atPath: "copyTest.dat", completionHandler: nil)
            smb.removeFile(atPath: "copyTestDest.dat", completionHandler: nil)
        }
        
        smb.connectShare(name: share) { (error) in
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
                    
                    smb.attributesOfItem(atPath: "copyTestDest.dat", completionHandler: { (file, error) in
                        XCTAssertNil(error)
                        XCTAssertEqual(file?.filesize, Int64(data.count))
                        expectation.fulfill()
                    })
                }
            }
        }
        
        wait(for: [expectation], timeout: 20)
    }
    
    func testMove() {
        let expectation = XCTestExpectation(description: #function)
        
        let smb = AMSMB2(url: server, credential: credential)!
        addTeardownBlock {
            smb.removeFile(atPath: "moveTest", completionHandler: nil)
            smb.removeFile(atPath: "moveTestDest", completionHandler: nil)
        }
        smb.connectShare(name: share) { (error) in
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
}

extension AMSMB2Tests {
    fileprivate func randomData(size: Int = 262144) -> Data {
        var keyData = Data(count: size)
        let count = keyData.count
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0)
        }
        if result == errSecSuccess {
            return keyData
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
    
    fileprivate func dummyFile(size: Int) -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dummyfile.dat")
        
        if FileManager.default.fileExists(atPath: url.path) {
            try! FileManager.default.removeItem(at: url)
        }
        
        let data = randomData(size: size)
        try! data.write(to: url)
        return url
    }
}
