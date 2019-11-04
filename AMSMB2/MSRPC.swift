//
//  MSRPC.swift
//  AMSMB2
//
//  Created by Amir Abbas Mousavian.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//

import Foundation

class MSRPC {
    static func parseNetShareEnumAllLevel1<DataType: DataProtocol>(data: DataType) throws -> [SMB2Share]
    {
        var shares = [SMB2Share]()
        let data = Data(data)
        /*
         Data Layout :
         
         struct _SHARE_INFO_1 {
         uint32 netname;  // pointer to NameContainer
         uint32 type;
         uint32 remark;   // pointer to NameContainer
         }
         
         struct NameContainer {
         uint32 maxCount;
         uint32 offset;
         uint32 actualCount;
         char* name; // null-terminated utf16le with (actualCount - 1) characters
         }
         
         struct _SHARE_INFO_1 {
         SHARE_INFO_1_CONTAINER[count] referantlist;
         NameContainer[count] nameslist;
         }
         */
        
        // First 48 bytes are header, _SHARE_INFO_1 is 12 bytes and "type" starts from 4th byte
        func typeOffset(_ i: Int) -> Int {
            return 48 + i * 12 + 4
        }
        
        // Count of shares to be enumerated, [44-47]
        let count = try data.scanInt(offset: 44, as: UInt32.self).unwrap()
        
        // start of nameString structs header size + (_SHARE_INFO_1 * count)
        var offset = 48 + count * 12
        for i in 0..<count {
            // Type of current share, see https://msdn.microsoft.com/en-us/library/windows/desktop/cc462916(v=vs.85).aspx
            let type = data.scanValue(offset: typeOffset(i), as: UInt32.self) ?? 0xffffffff
            
            // Parse name part
            let nameActualCount = try data.scanInt(offset: offset + 8, as: UInt32.self).unwrap()
            
            offset += 12
            if offset + nameActualCount * 2 > data.count {
                throw POSIXError(.EBADRPC)
            }
            
            // Getting utf16le data, omitting nul char
            let nameStringData = data.dropFirst(offset).prefix((nameActualCount - 1) * 2)
            let nameString: String = nameActualCount > 1 ?
                (String(data: nameStringData, encoding: .utf16LittleEndian) ?? "") : ""
            
            offset += nameActualCount * 2
            if nameActualCount % 2 == 1 {
                // if name length is odd, there is an extra nul char pad for alignment.
                offset += 2
            }
            
            // Parse comment part
            let commentActualCount = try data.scanInt(offset: offset + 8, as: UInt32.self).unwrap()
            
            offset += 12
            if offset + commentActualCount * 2 > data.count {
                throw POSIXError(.EBADRPC)
            }
            
            // Getting utf16le data, omitting nul char
            let commentStringData = data.dropFirst(offset).prefix((commentActualCount - 1) * 2)
            let commentString: String = commentActualCount > 1 ?
                (String(data: commentStringData, encoding: .utf16LittleEndian) ?? "") : ""
            
            offset += commentActualCount * 2
            
            if commentActualCount % 2 == 1 {
                // if name length is odd, there is an extra nul char pad for alignment.
                offset += 2
            }
            
            shares.append(.init(name: nameString, props: ShareProperties(rawValue: type), comment: commentString))
            
            if offset > data.count {
                break
            }
        }
        
        return shares
    }
    
    enum DCECommand: UInt8 {
        case request = 0x00
        case bind = 0x0b
    }
    
    private static func dceHeader(command: DCECommand, callId: UInt32) -> Data {
        var headerData = Data()
        // Version major, version minor, packet type = 'bind', packet flags
        headerData.append(contentsOf: [0x05, 0, command.rawValue, 0x03])
        // Representation = little endian/ASCII.
        headerData.append(value: 0x10 as UInt32)
        // data length
        headerData.append(value: 0 as UInt16)
        // Auth len
        headerData.append(value: 0 as UInt16)
        // Call ID
        headerData.append(value: callId as UInt32)
        return headerData
    }
    
    private static func setDCELength(_ data: inout Data) {
        let count = data.count
        data[8] = UInt8(count & 0xff)
        data[9] = UInt8((count >> 8) & 0xff)
    }
    
    static func srvsvcBindData() -> Data {
        var reqData = dceHeader(command: .bind, callId: 1)
        // Max Xmit size
        reqData.append(value: Int16.max)
        // Max Recv size
        reqData.append(value: Int16.max)
        // Assoc group
        reqData.append(value: 0 as UInt32)
        // Num Ctx Item
        reqData.append(value: 1 as UInt32)
        // ContextID
        reqData.append(value: 0 as UInt16)
        // Num Trans Items
        reqData.append(value: 1 as UInt16)
        // SRVSVC UUID
        let srvsvcUuid = UUID(uuidString: "4b324fc8-1670-01d3-1278-5a47bf6ee188")!
        reqData.append(value: srvsvcUuid)
        // SRVSVC Version = 3.0
        reqData.append(value: 3 as UInt16)
        reqData.append(value: 0 as UInt16)
        // NDR UUID
        let ndruuid = UUID(uuidString: "8a885d04-1ceb-11c9-9fe8-08002b104860")!
        reqData.append(value: ndruuid)
        // NDR version = 2.0
        reqData.append(value: 2 as UInt16)
        reqData.append(value: 0 as UInt16)
        
        setDCELength(&reqData)
        return reqData
    }
    
    static func requestNetShareEnumAll(server serverName: String, level: UInt32 = 1) -> Data {
        let serverNameData = serverName.data(using: .utf16LittleEndian)!
        let serverNameLen = UInt32(serverName.count + 1)
        
        var reqData = dceHeader(command: .request, callId: 0)
        // Alloc hint
        reqData.append(value: 72 as UInt32)
        // Context ID
        reqData.append(value: 0 as UInt16)
        // OpNum = NetShareEnumAll
        reqData.append(value: 0x0f as UInt16)
        
        // Pointer to server UNC
        // Referent ID
        reqData.append(value: 1 as UInt32)
        // Max count
        reqData.append(value: serverNameLen as UInt32)
        // Offset
        reqData.append(value: 0 as UInt32)
        // Max count
        reqData.append(value: serverNameLen as UInt32)
        
        // The server name
        reqData.append(serverNameData)
        reqData.append(value: 0 as UInt16) // null termination
        if serverNameLen % 2 == 1 {
            reqData.append(value: 0 as UInt16) // padding
        }
        
        // Level 1
        reqData.append(value: level as UInt32)
        // Ctr
        reqData.append(value: 1 as UInt32)
        // Referent ID
        reqData.append(value: 1 as UInt32)
        // Count/Null Pointer to NetShareInfo1
        reqData.append(value: 0 as UInt32)
        // Null Pointer to NetShareInfo1
        reqData.append(value: 0 as UInt32)
        // Max Buffer
        reqData.append(value: 0xffffffff as UInt32)
        // Resume Referent ID
        reqData.append(value: 1 as UInt32)
        // Resume
        reqData.append(value: 0 as UInt32)
        
        setDCELength(&reqData)
        return reqData
    }
    
    static func validateBindData<DataType: DataProtocol>(_ recvBindData: DataType) throws {
        // Bind command result is exactly 68 bytes here. 54 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData.count < 68 {
            throw POSIXError(.EBADMSG, description:  "Binding failure: Invalid size")
        }
        
        // These bytes contains Ack result, 30 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        let byte44 = recvBindData[recvBindData.index(recvBindData.startIndex, offsetBy: 44)]
        let byte45 = recvBindData[recvBindData.index(recvBindData.startIndex, offsetBy: 45)]
        if byte44 > 0 || byte45 > 0 {
            // Ack result is not acceptance (0x0000)
            let errorCode = UInt16(byte44) + (UInt16(byte45) << 8)
            let errorCodeString = String(errorCode, radix: 16, uppercase: false)
            throw POSIXError(.EBADMSG, description:  "Binding failure: \(errorCodeString)")
        }
    }
}
