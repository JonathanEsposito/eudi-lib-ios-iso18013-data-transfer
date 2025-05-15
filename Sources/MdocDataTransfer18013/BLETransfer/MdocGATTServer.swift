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

//  MdocGATTServer.swift
import Foundation
import CoreBluetooth
import Logging
import MdocDataModel18013
import MdocSecurity18013

/// BLE Gatt server implementation of mdoc transfer manager
public class MdocGattServer: NSObject, @unchecked Sendable, ObservableObject {
	var peripheralManager: CBPeripheralManager!
	var remoteCentral: CBCentral!
	var stateCharacteristic: CBMutableCharacteristic!
	var server2ClientCharacteristic: CBMutableCharacteristic!
	public var deviceEngagement: DeviceEngagement?
	public var deviceRequest: DeviceRequest?
	public var sessionEncryption: SessionEncryption?
	public var iaca: [SecCertificate]
	public var dauthMethod: DeviceAuthMethod
	public var readerName: String?
	public var qrCodePayload: String?
	public weak var delegate: (any MdocOfflineDelegate)?
	public var advertising: Bool = false
	public var error: Error? { willSet { handleErrorSet(newValue) }}
	public var status: TransferStatus = .initializing { willSet { Task { @MainActor in await handleStatusChange(newValue) } } }
	public var unlockData: [String: Data]!
	var readBuffer = Data()
	var sendBuffer = Data()
	var sendBufferBlockToSendIndex: Int = 0
	var subscribeCount: Int = 0
	var initSuccess: Bool = false
	
	var isPreview: Bool {
		ProcessInfo.processInfo.environment["XCODE_RUNNING_FOR_PREVIEWS"] == "1"
	}
	
	var isInErrorState: Bool { status == .error }
	
	public init(trustedCertificates: [SecCertificate], deviceAuthMethod: DeviceAuthMethod) {
		self.iaca = trustedCertificates
		self.dauthMethod = deviceAuthMethod
		status = .initialized
		
		super.init()
		
		initPeripheralManager()
		initSuccess = true
	}
	
	fileprivate func initPeripheralManager() {
		guard peripheralManager == nil else { return }
		logger.info("Initializing BLE peripheral manager")
		peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
		subscribeCount = 0
	}
	
	/// Returns true if the peripheralManager state is poweredOn
	public var isBlePoweredOn: Bool { peripheralManager.state == .poweredOn }
	
	/// Returns true if the peripheralManager state is unauthorized
	public var isBlePermissionDenied: Bool { peripheralManager.state == .unauthorized }
	
	// Create a new device engagement object and start the device engagement process.
	///
	/// ``qrCodePayload`` is set to QR code data corresponding to the device engagement.
	public func performDeviceEngagement(secureArea: any SecureArea, crv: CoseEcCurve, rfus: [String]? = nil) async throws {
		guard !isPreview && !isInErrorState else {
			logger.info("Current status is \(status)")
			return
		}
		// Check that the class is in the right state to start the device engagement process. It will fail if the class is in any other state.
		guard status == .initialized || status == .disconnected || status == .responseSent else { error = MdocHelpers.makeError(code: .unexpected_error, str: error?.localizedDescription ?? "Not initialized!"); return }
		deviceEngagement = DeviceEngagement(isBleServer: true, rfus: rfus)
		try await deviceEngagement!.makePrivateKey(crv: crv, secureArea: secureArea)
		sessionEncryption = nil
#if os(iOS)
		qrCodePayload = deviceEngagement!.getQrCodePayload()
		logger.info("Created qrCode payload: \(qrCodePayload!)")
#endif
		// Check that the peripheral manager has been authorized to use Bluetooth.
		guard peripheralManager.state != .unauthorized else { error = MdocHelpers.makeError(code: .bleNotAuthorized); return }
		start()
	}
	
	func buildServices(uuid: String) {
		let bleUserService = CBMutableService(type: CBUUID(string: uuid), primary: true)
		stateCharacteristic = CBMutableCharacteristic(type: MdocServiceCharacteristic.state.uuid, properties: [.notify, .writeWithoutResponse], value: nil, permissions: [.writeable])
		let client2ServerCharacteristic = CBMutableCharacteristic(type: MdocServiceCharacteristic.client2Server.uuid, properties: [.writeWithoutResponse], value: nil, permissions: [.writeable])
		server2ClientCharacteristic = CBMutableCharacteristic(type: MdocServiceCharacteristic.server2Client.uuid, properties: [.notify], value: nil, permissions: [])
		bleUserService.characteristics = [stateCharacteristic, client2ServerCharacteristic, server2ClientCharacteristic]
		peripheralManager.removeAllServices()
		peripheralManager.add(bleUserService)
	}
	
	func start() {
		guard !isPreview && !isInErrorState else {
			logger.info("Current status is \(status)")
			return
		}
		if peripheralManager.state == .poweredOn {
			logger.info("Peripheral manager powered on")
			error = nil
			guard let uuid = deviceEngagement?.ble_uuid else {
				logger.error("BLE initialization error")
				return
			}
			buildServices(uuid: uuid)
			let advertisementData: [String: Any] = [CBAdvertisementDataServiceUUIDsKey: [CBUUID(string: uuid)], CBAdvertisementDataLocalNameKey: uuid]
			// advertise the peripheral with the short UUID
			peripheralManager.startAdvertising(advertisementData)
			advertising = true
			status = .qrEngagementReady
		} else {
			// once bt is powered on, advertise
			if peripheralManager.state == .resetting {
				DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.start()}
			} else { logger.info("Peripheral manager powered off") }
		}
	}
	
	public func stop() {
		guard !isPreview else { return }
		if let peripheralManager, peripheralManager.isAdvertising { peripheralManager.stopAdvertising() }
		qrCodePayload = nil
		advertising = false
		subscribeCount = 0
		if let pk = deviceEngagement?.privateKey { Task { @MainActor in try? await pk.secureArea.deleteKey(id: pk.privateKeyId); deviceEngagement?.privateKey = nil } }
		if status == .error && initSuccess { status = .initializing }
	}
	
	func handleStatusChange(_ newValue: TransferStatus) async {
		guard !isPreview && !isInErrorState else { return }
		logger.log(level: .info, "Transfer status will change to \(newValue)")
		delegate?.didChangeStatus(newValue)
		if newValue == .requestReceived {
			peripheralManager.stopAdvertising()
			do {
				let request = try await MdocHelpers.decodeRequest(deviceEngagement: deviceEngagement,
																  iaca: iaca,
																  requestData: readBuffer,
																  handOver: BleTransferMode.qrHandover)
				self.deviceRequest = request.deviceRequest
				sessionEncryption = request.sessionEncryption
				delegate?.didReceiveRequest(request.userRequestInfo, handleSelected: userSelected)
			} catch {
				logger.error("Error sending data: \(error)")
				var sessionData: SessionData {
					do {
						throw error
					} catch ErrorCode.requestDecodeError {
						return SessionData(status: .errorCBORDecoding)
					} catch {
						return SessionData(status: .errorSessionEncryption)
					}
				}
				
				sendBuffer = Data(sessionData.encode())
				sendBufferBlockToSendIndex = 0
				sendDataWithUpdates()
				
				self.error = error
			}
		} else if newValue == .initialized {
			initPeripheralManager()
		} else if newValue == .disconnected && status != .disconnected {
			stop()
		}
	}
	
	public func userSelected(request: UserRequestInfo, selectedItems: RequestItems, attestations: [String: (IssuerSigned, CoseKeyPrivate)]) async {
		status = .userSelected
		
		defer {
			logger.info("Prepare \(sendBuffer.count) bytes to send")
			sendBufferBlockToSendIndex = 0
			sendDataWithUpdates()
		}
		
		do {
			let deviceResponseToSend = try await MdocHelpers.getDeviceResponseToSend(userRequestInfo: request,
																					 attestations: attestations,
																					 selectedItems: selectedItems,
																					 sessionEncryption: sessionEncryption,
																					 eReaderKey: sessionEncryption!.sessionKeys.publicKey,
																					 deviceAuthMethod: dauthMethod,
																					 unlockData: [:])
			
			sendBuffer = await MdocHelpers.getSessionDataToSend(sessionEncryption: sessionEncryption, docToSend: deviceResponseToSend)
		} catch {
			logger.error("Error sending data: \(error)")
			self.error = error
			
			let sessionData = SessionData(status: .errorSessionEncryption)
			sendBuffer = Data(sessionData.encode())
		}
	}
	
	func handleErrorSet(_ newValue: Error?) {
		guard let newValue else { return }
		status = .error
		delegate?.didFinishedWithError(newValue)
		logger.log(level: .error, "Transfer error \(newValue) (\(newValue.localizedDescription)")
	}
	
	func sendDataWithUpdates() {
		guard !isPreview else { return }
		guard sendBuffer.count > sendBufferBlockToSendIndex else {
			status = .responseSent
			logger.info("Finished sending BLE data")
			stop()
			return
		}
		
		let maxBlockSize = remoteCentral.maximumUpdateValueLength - BLEMessage.maxLengthPadding
		let (blockToSend, nextIndex) = MdocHelpers.nextBlockToSend(message: sendBuffer, blockIndex: sendBufferBlockToSendIndex, maxBlockSize: maxBlockSize)
		
		let sentSuccessfully = peripheralManager.updateValue(blockToSend, for: server2ClientCharacteristic, onSubscribedCentrals: [remoteCentral])
		if sentSuccessfully {
			sendBufferBlockToSendIndex = nextIndex
			sendDataWithUpdates()
		}
	}

}

// MARK: - Peripheral Manager Delegate

extension MdocGattServer: CBPeripheralManagerDelegate {
	
	public func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
		if sendBuffer.count > sendBufferBlockToSendIndex { self.sendDataWithUpdates() }
	}
	
	public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
		logger.info("CBPeripheralManager didUpdateState:")
		logger.info(peripheral.state == .poweredOn ? "Powered on" : peripheral.state == .unauthorized ? "Unauthorized" : peripheral.state == .unsupported ? "Unsupported" : "Powered off")
		if peripheral.state == .poweredOn, qrCodePayload != nil { start() }
	}
	
	public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
		if requests[0].characteristic.uuid == MdocServiceCharacteristic.state.uuid, let header = requests[0].value?.first {
			if header == BleTransferMode.startRequest.first! {
				logger.info("Start request received to state characteristic") // --> start
				status = .started
				readBuffer.removeAll()
			} else if header == BleTransferMode.endRequest.first! {
				guard status == .responseSent else {
					logger.error("State END command rejected. Not in responseSent state")
					peripheral.respond(to: requests[0], withResult: .unlikelyError)
					return
				}
				logger.info("End received to state characteristic") // --> end
				status = .disconnected
			}
		} else if requests[0].characteristic.uuid == MdocServiceCharacteristic.client2Server.uuid {
			for request in requests {
				guard let data = request.value, let header = data.first else { continue }
				let bStart = header == BleTransferMode.startData.first
				let bEnd = header == BleTransferMode.endData.first
				if data.count > 1 { readBuffer.append(data.advanced(by: 1)) }
				if !bStart && !bEnd { logger.warning("Not a valid request block: \(data)") }
				if bEnd { status = .requestReceived  }
			}
		}
		peripheral.respond(to: requests[0], withResult: .success)
	}
	
	public func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
		guard status == .qrEngagementReady else { return }
		let mdocCbc = MdocServiceCharacteristic(uuid: characteristic.uuid)
		logger.info("Remote central \(central.identifier) connected for \(mdocCbc?.rawValue ?? "") characteristic")
		remoteCentral = central
		if characteristic.uuid == MdocServiceCharacteristic.state.uuid || characteristic.uuid == MdocServiceCharacteristic.server2Client.uuid { subscribeCount += 1 }
		if subscribeCount > 1 { status = .connected }
	}
	
	public func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
		let mdocCbc = MdocServiceCharacteristic(uuid: characteristic.uuid)
		logger.info("Remote central \(central.identifier) disconnected for \(mdocCbc?.rawValue ?? "") characteristic")
	}
}
