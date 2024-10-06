//
//  MSRPC.swift
//  AMSMB2
//
//  Created by Amir Abbas on 7/31/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation

enum MSRPC {
    struct NetShareEnumAllLevel1: IOCtlReply {
        let shares: [SMB2Share]

        init(shares: [SMB2Share]) {
            self.shares = shares
        }

        init(data: Data) throws {
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
                48 + i * 12 + 4
            }

            var shares = [SMB2Share]()
            // Count of shares to be enumerated, [44-47]
            let count = try data.scanInt(offset: 44, as: UInt32.self).unwrap()

            // start of nameString structs header size + (_SHARE_INFO_1 * count)
            var offset = 48 + count * 12
            for i in 0..<count {
                // Type of current share, see https://msdn.microsoft.com/en-us/library/windows/desktop/cc462916(v=vs.85).aspx
                let type = data.scanValue(offset: typeOffset(i), as: UInt32.self) ?? 0xffff_ffff

                // Parse name part
                let nameActualCount = try data.scanInt(offset: offset + 8, as: UInt32.self).unwrap()

                offset += 12
                if offset + nameActualCount * 2 > data.count {
                    throw POSIXError(.EBADRPC)
                }

                // Getting utf16le data, omitting nul char
                let nameStringData = data.dropFirst(offset).prefix((nameActualCount - 1) * 2)
                let nameString: String =
                    nameActualCount > 1
                        ? (String(data: nameStringData, encoding: .utf16LittleEndian) ?? "") : ""

                offset += nameActualCount * 2
                if nameActualCount % 2 == 1 {
                    // if name length is odd, there is an extra nul char pad for alignment.
                    offset += 2
                }

                // Parse comment part
                let commentActualCount = try data.scanInt(offset: offset + 8, as: UInt32.self)
                    .unwrap()

                offset += 12
                if offset + commentActualCount * 2 > data.count {
                    throw POSIXError(.EBADRPC)
                }

                // Getting utf16le data, omitting nul char
                let commentStringData = data.dropFirst(offset).prefix((commentActualCount - 1) * 2)
                let commentString: String =
                    commentActualCount > 1
                        ? (String(data: commentStringData, encoding: .utf16LittleEndian) ?? "") : ""

                offset += commentActualCount * 2

                if commentActualCount % 2 == 1 {
                    // if name length is odd, there is an extra nul char pad for alignment.
                    offset += 2
                }

                shares.append(
                    .init(
                        name: nameString, props: ShareProperties(rawValue: type),
                        comment: commentString
                    )
                )

                if offset > data.count {
                    break
                }
            }

            self.shares = shares
        }
    }

    struct DCEHeader: IOCtlArgument {
        enum Command: UInt8 {
            case request = 0x00
            case bind = 0x0b
        }

        typealias Element = UInt8

        static var count: Int { 16 }

        let command: Command
        var length: UInt16
        let callId: UInt32

        var regions: [Data] {
            [
                // Version major, version minor, packet type = 'bind', packet flags
                .init([0x05, 0x00, command.rawValue, 0x03]),
                // Representation = little endian/ASCII.
                .init(value: 0x10 as UInt32),
                // data length
                .init(value: length),
                // Auth len
                .init(value: 0 as UInt16),
                // Call ID
                .init(value: callId as UInt32),
            ]
        }

        init(command: Command, length: UInt16, callId: UInt32) {
            self.command = command
            self.length = length
            self.callId = callId
        }

        init(command: Command, callId: UInt32, payload: [Data]) {
            self.command = command
            self.length = UInt16(Self.count + payload.joined().count)
            self.callId = callId
        }
    }

    struct SrvsvcBindData: IOCtlArgument {
        typealias Element = UInt8

        var regions: [Data] {
            let srvsvcUuid = UUID(uuidString: "4b324fc8-1670-01d3-1278-5a47bf6ee188")!
            let ndruuid = UUID(uuidString: "8a885d04-1ceb-11c9-9fe8-08002b104860")!
            let payload: [Data] = [
                // Max Xmit size
                .init(value: Int16.max),
                // Max Recv size
                .init(value: Int16.max),
                // Assoc group
                .init(value: 0 as UInt32),
                // Num Ctx Item
                .init(value: 1 as UInt32),
                // ContextID
                .init(value: 0 as UInt16),
                // Num Trans Items
                .init(value: 1 as UInt16),
                // SRVSVC UUID
                .init(value: srvsvcUuid),
                // SRVSVC Version = 3.0
                .init(value: 3 as UInt16),
                .init(value: 0 as UInt16),
                // NDR UUID
                .init(value: ndruuid),
                // NDR version = 2.0
                .init(value: 2 as UInt16),
                .init(value: 0 as UInt16),
            ]
            return DCEHeader(command: .bind, callId: 1, payload: payload).regions + payload
        }
    }

    struct NetShareEnumAllRequest: IOCtlArgument {
        typealias Element = UInt8

        let serverName: String
        let level: UInt32 = 1

        var regions: [Data] {
            let serverNameData = serverName.data(using: .utf16LittleEndian)!
            let serverNameLen = UInt32(serverNameData.count / 2 + 1)

            let payload: [Data] = [
                // Alloc hint
                .init(value: 72 as UInt32),
                // Context ID
                .init(value: 0 as UInt16),
                // OpNum = NetShareEnumAll
                .init(value: 0x0f as UInt16),

                // Pointer to server UNC
                // Referent ID
                .init(value: 1 as UInt32),
                // Max count
                .init(value: serverNameLen as UInt32),
                // Offset
                .init(value: 0 as UInt32),
                // Max count
                .init(value: serverNameLen as UInt32),

                // The server name
                .init(serverNameData),
                serverNameLen % 2 == 1 ? .init(value: 0 as UInt32) : .init(value: 0 as UInt16),

                // Level 1
                .init(value: level as UInt32),
                // Ctr
                .init(value: 1 as UInt32),
                // Referent ID
                .init(value: 1 as UInt32),
                // Count/Null Pointer to NetShareInfo1
                .init(value: 0 as UInt32),
                // Null Pointer to NetShareInfo1
                .init(value: 0 as UInt32),
                // Max Buffer
                .init(value: 0xffff_ffff as UInt32),
                // Resume Referent ID
                .init(value: 1 as UInt32),
                // Resume
                .init(value: 0 as UInt32),
            ]

            return DCEHeader(command: .request, callId: 0, payload: payload).regions + payload
        }
    }

    static func validateBindData<DataType: DataProtocol>(_ recvBindData: DataType) throws {
        // Bind command result is exactly 68 bytes here. 54 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        if recvBindData.count < 68 {
            throw POSIXError(.EBADMSG, description: "Binding failure: Invalid size")
        }

        // These bytes contains Ack result, 30 + ("\PIPE\srvsvc" ascii length + 1 byte padding).
        let byte44 = recvBindData[recvBindData.index(recvBindData.startIndex, offsetBy: 44)]
        let byte45 = recvBindData[recvBindData.index(recvBindData.startIndex, offsetBy: 45)]
        if byte44 > 0 || byte45 > 0 {
            // Ack result is not acceptance (0x0000)
            let errorCode = UInt16(byte44) + (UInt16(byte45) << 8)
            let errorCodeString = String(errorCode, radix: 16, uppercase: false)
            throw POSIXError(.EBADMSG, description: "Binding failure: \(errorCodeString)")
        }
    }
}
