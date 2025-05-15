/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//  ServiceDefinition.swift
import Foundation
import CoreBluetooth
import SwiftCBOR

/// The enum BleTransferMode defines the two roles in the communication, which can be a server or a client.
///
/// The four static variables are used to signal the start and the end of the communication.
/// This is done by sending the bytes 0x01 and 0x02 for the start and end of the communication, respectively.
/// For the start and end of the data transmission, the bytes 0x01 and 0x00 are used.
public enum BleTransferMode: Sendable {
	case server
	case client
	// signals for coordination
	static let startRequest: [UInt8] = [0x01]
	static let endRequest: [UInt8] = [0x02]
	static let startData: [UInt8] = [0x01]
	static let endData: [UInt8] = [0x00]
	public static let qrHandover = CBOR.null
}

public enum BLEMessage {
	static let maxLengthPadding = 3
	enum Header {
		static let endOfMessageByte: UInt8 = 0x00
		static let endOfMessageData = Data([Self.endOfMessageByte])
		static let partOfMessageByte: UInt8 = 0x01
		static let partOfMessageData = Data([Self.partOfMessageByte])
	}
}

/// mdoc service characteristic definitions (mdoc is the GATT server)
public enum MdocServiceCharacteristic: String, Sendable {
	case state = "00000001-A123-48CE-896B-4C76973373E6"
	case client2Server = "00000002-A123-48CE-896B-4C76973373E6"
	case server2Client = "00000003-A123-48CE-896B-4C76973373E6"
}

extension MdocServiceCharacteristic {
	init?(uuid: CBUUID) {	self.init(rawValue: uuid.uuidString.uppercased()) }
	public var uuid: CBUUID { CBUUID(string: rawValue) }
}
