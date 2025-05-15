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
 limitations under the License®.
 */

//  Helpers.swift
import Foundation
import CoreBluetooth
import Combine
import MdocDataModel18013
import MdocSecurity18013
#if canImport(UIKit)
import UIKit
#endif
import AVFoundation
import SwiftCBOR
import Logging
import X509

public typealias RequestItems = [String: [NameSpace: [RequestItem]]]

extension ItemsRequest {
	var requestItems: RequestItems {
		[self.docType: self.requestNameSpaces.nameSpaces
			.mapValues(\.dataElements)
			.mapValues { $0.map { RequestItem(elementIdentifier: $0.key, displayName: nil, intentToRetain: $0.value)  } }]
	}
}

/// Helper methods
public class MdocHelpers {
	
	static var errorNoDocumentsDescriptionKey: String { "doctype_not_found" }
	static func getErrorNoDocuments(_ docType: String) -> Error { NSError(domain: "\(MdocGattServer.self)", code: 0, userInfo: ["key": Self.errorNoDocumentsDescriptionKey, "%s": docType]) }
	
	public static func makeError(code: ErrorCode, str: String? = nil) -> NSError {
		let errorMessage = str ?? NSLocalizedString(code.description, comment: code.description)
		logger.error(Logger.Message(unicodeScalarLiteral: errorMessage))
		return NSError(domain: "\(MdocGattServer.self)", code: code.rawValue, userInfo: [NSLocalizedDescriptionKey: errorMessage, "key": code.description])
	}
	
	public static func getSessionDataToSend(sessionEncryption: SessionEncryption?, docToSend: DeviceResponse) async -> Data {
		do {
			guard var sessionEncryption else {
				throw ErrorCode.sessionEncryptionNotInitialized
			}
			
			if docToSend.documents == nil { logger.error("Could not create documents to send") }
			let cborToSend = docToSend.toCBOR(options: CBOROptions())
			let clearBytesToSend = cborToSend.encode()
			let cipherData = try await sessionEncryption.encrypt(clearBytesToSend)
			let sessionData = SessionData(cipher_data: cipherData, status: .sessionTermination)
			
			return Data(sessionData.encode(options: CBOROptions()))
		} catch {
			logger.error("\(error)")
			let sessionData = SessionData(cipher_data: nil, status: .errorSessionEncryption)
			return Data(sessionData.encode(options: CBOROptions()))
		}
	}
	
	/// Decrypt the contents of a data object and return a ``DeviceRequest`` object if the data represents a valid device request. If the data does not represent a valid device request, the function returns nil.
	/// - Parameters:
	///   - deviceEngagement: deviceEngagement
	///   - docs: IssuerSigned documents
	///   - iaca: Root certificates trusted
	///   - dauthMethod: Method to perform mdoc authentication
	///   - handOver: handOver structure
	/// - Returns: A ``DeviceRequest`` object
	public static func decodeRequest(deviceEngagement: DeviceEngagement?,
									 iaca: [SecCertificate],
									 requestData: Data,
									 handOver: CBOR) async throws -> (sessionEncryption: SessionEncryption,
																	  deviceRequest: DeviceRequest,
																	  userRequestInfo: UserRequestInfo) {
		guard var sessionEstablishment = try SessionEstablishment(requestData) else {
			logger.error("Request Data cannot be decoded to session establishment")
			throw ErrorCode.requestDecodeError
		}
		
		guard let deviceEngagement else {
			logger.error("Device Engagement not initialized")
			throw ErrorCode.deviceEngagementMissing
		}
		
		// init session-encryption object from session establish message and device engagement, decrypt data
		let sessionEncryption = SessionEncryption(se: sessionEstablishment, de: deviceEngagement, handOver: handOver)
		
		guard var sessionEncryption else {
			logger.error("Session Encryption not initialized")
			throw ErrorCode.sessionEncryptionNotInitialized
		}
		
		guard let requestData = try await sessionEncryption.decrypt(sessionEstablishment.data) else {
			logger.error("Request data cannot be decrypted")
			throw ErrorCode.deviceRequestFailedToDecrypt
		}
		
		guard let deviceRequest = DeviceRequest(data: requestData) else {
			logger.error("Decrypted data cannot be decoded")
			throw ErrorCode.requestDecodeError
		}
		
		var userRequestInfo = deviceRequest.userRequestInfo
		
		// Reader validation
		let mdocAuth = MdocReaderAuthentication(transcript: sessionEncryption.transcript)
		if let docR = deviceRequest.docRequests.first,
		   let readerAuthRawCBOR = docR.readerAuthRawCBOR,
		   case let certData = docR.readerCertificates,
		   !certData.isEmpty {
			do {
				let x509 = try X509.Certificate(derEncoded: [UInt8](certData.first!))
				let (b, reasonFailure) = try mdocAuth.validateReaderAuth(readerAuthCBOR: readerAuthRawCBOR, readerAuthX5c: certData, itemsRequestRawData: docR.itemsRequestRawData!, rootCerts: iaca)
				userRequestInfo.readerCertificateIssuer = MdocHelpers.getCN(from: x509.subject.description)
				userRequestInfo.readerAuthValidated = b
				if let reasonFailure { userRequestInfo.readerCertificateValidationMessage = reasonFailure }
			} catch {
				logger.error("\(error)")
				userRequestInfo.readerCertificateValidationMessage = "\(error)"
			}
		}
		
		return (sessionEncryption: sessionEncryption, deviceRequest: deviceRequest, userRequestInfo: userRequestInfo)
	}
	
	/// Construct ``DeviceResponse`` object to present from wallet data and input device request
	/// - Parameters:
	///   - deviceRequest: Device request coming from verifier
	///   - issuerSigned: Map of document ID to issuerSigned cbor data
	///   - selectedItems: Selected items from user (Map of Document ID to namespaced items)
	///   - sessionEncryption: Session Encryption data structure
	///   - eReaderKey: eReader (verifier) ephemeral public key
	///   - devicePrivateKeys: Device Private keys
	///   - sessionTranscript: Session Transcript object
	///   - deviceAuthMethod: Mdoc Authentication method
	/// - Returns: Device response object
	public static func getDeviceResponseToSend(userRequestInfo: UserRequestInfo,
											   attestations: [String: (IssuerSigned, CoseKeyPrivate)],
											   selectedItems: RequestItems,
											   sessionEncryption: SessionEncryption? = nil,
											   eReaderKey: CoseKey? = nil,
											   sessionTranscript: SessionTranscript? = nil,
											   deviceAuthMethod: DeviceAuthMethod,
											   unlockData: [String: Data]) async throws -> DeviceResponse {
		var documentsToAdd = [Document]()
		
		let issuedDocTypes = attestations.values.map(\.0.issuerAuth.mso.docType)
		var docErrors: [[DocType: UInt64]] = userRequestInfo.itemsRequested.keys // Documents the user opted out off or where not available
			.filter { !issuedDocTypes.contains($0) }
			.map { [$0: 0] }
		
		let selectedDocIds = selectedItems.keys
		for selectedDocId in selectedDocIds {
			guard let (doc, devicePrivateKey) = attestations[selectedDocId] else { continue }
			
			let selectedNameSpaces = selectedItems[selectedDocId]!.keys
			let (nsItemsToAdd, nsErrorsToAdd) = selectedNameSpaces.reduce(into: (selected: [NameSpace: [IssuerSignedItem]](), errors: [NameSpace: ErrorItems]())) { result, reqNamespace in
				let attributes = doc.issuerNameSpaces?[reqNamespace]
				
				// Attributes
				let selectedAttributeIdentifiers = selectedItems[selectedDocId]![reqNamespace]!.map(\.elementIdentifier)
				let selectedAttributes = attributes?.filter { selectedAttributeIdentifiers.contains($0.elementIdentifier) } ?? []
				result.selected[reqNamespace] = selectedAttributes.isEmpty ? nil : selectedAttributes
				
				// Attributes user opted out or where not available
				let requestedAttributeIdentifiers = userRequestInfo.itemsRequested[doc.issuerAuth.mso.docType]![reqNamespace]!.map(\.elementIdentifier)
				let optOutAttributes = Set(requestedAttributeIdentifiers).subtracting(selectedAttributeIdentifiers)
				result.errors[reqNamespace] = optOutAttributes.isEmpty ? nil : Dictionary(grouping: optOutAttributes, by: { $0 }).mapValues { _ in 0 }
			} // end ns for
			
			let errors: Errors? = nsErrorsToAdd.isEmpty ? nil : Errors(errors: nsErrorsToAdd)
			
			if !nsItemsToAdd.isEmpty {
				let issuerAuthToAdd = doc.issuerAuth
				let issToAdd = IssuerSigned(issuerNameSpaces: IssuerNameSpaces(nameSpaces: nsItemsToAdd), issuerAuth: issuerAuthToAdd)
				var devSignedToAdd: DeviceSigned?
				let sessionTranscript = sessionEncryption?.transcript ?? sessionTranscript
				if let eReaderKey, let sessionTranscript {
					let authKeys = CoseKeyExchange(publicKey: eReaderKey, privateKey: devicePrivateKey)
					let mdocAuth = MdocAuthentication(transcript: sessionTranscript, authKeys: authKeys)
					let devAuth = try await mdocAuth.getDeviceAuthForTransfer(docType: doc.issuerAuth.mso.docType, dauthMethod: deviceAuthMethod, unlockData: unlockData[selectedDocId])
					devSignedToAdd = DeviceSigned(deviceAuth: devAuth)
				}
				let docToAdd = Document(docType: doc.issuerAuth.mso.docType, issuerSigned: issToAdd, deviceSigned: devSignedToAdd, errors: errors)
				documentsToAdd.append(docToAdd)
			} else {
				docErrors.append([doc.issuerAuth.mso.docType: 0])
			}
		} // end doc for
		
		let documentErrors: [DocumentError] = docErrors.map(DocumentError.init(docErrors:))
		let deviceResponseToSend = DeviceResponse(version: DeviceResponse.defaultVersion, documents: documentsToAdd, documentErrors: documentErrors, status: 0)
		return deviceResponseToSend
	}
	
	/// Creates a block for a given block id from a data object. The block size is limited to maxBlockSize bytes.
	/// - Parameters:
	///   - message: The data object to be sent
	///   - blockIndex: The start index of the block to be sent
	///   - maxBlockSize: The maximum block size
	/// - Returns: (blockToSend:The data block to send, nextBlockIndex: start index of the next block to send)
	public static func nextBlockToSend(message: Data, blockIndex: Int, maxBlockSize: Int) -> (Data, Int) {
		let blockSize = min(maxBlockSize, message.count - blockIndex)
		
		// Calculate the data range of our request data to send
		let nextBlockIndex = blockIndex + blockSize
		let rangeToSend = blockIndex..<nextBlockIndex
		
		// Copy the correct request data range to send
		var blockToSend = message.subdata(in: rangeToSend)
		
		// Add package prefix to the data package to send
		let blockHeader = message.count > nextBlockIndex ? BLEMessage.Header.partOfMessageData : BLEMessage.Header.endOfMessageData
		blockToSend = blockHeader + blockToSend
		
		// Log what we will send
		let blockCount = (Double(message.count) / Double(blockSize)).rounded(.up)
		logger.info("Sending response of total bytes \(message.count) in \(blockCount) blocks and block size: \(blockSize)")
		
		return (blockToSend, nextBlockIndex)
	}
	
#if os(iOS)
	
	/// Check if BLE access is allowed, and if not, present a dialog that opens settings
	/// - Parameters:
	///   - vc: The view controller that will present the settings
	///   - action: The action to perform
	@MainActor
	public static func checkBleAccess(_ vc: UIViewController, action: @escaping () -> Void) {
		switch CBManager.authorization {
		case .denied:
			// "Denied, request permission from settings"
			presentSettings(vc, msg: NSLocalizedString("Bluetooth access is denied", comment: ""))
		case .restricted:
			logger.warning("Restricted, device owner must approve")
		case .allowedAlways:
			// "Authorized, proceed"
			DispatchQueue.main.async { action() }
		case .notDetermined:
			DispatchQueue.main.async { action() }
		@unknown default:
			logger.info("Unknown authorization status")
		}
	}
	
	/// Check if the user has given permission to access the camera. If not, ask them to go to the settings app to give permission.
	/// - Parameters:
	///   - vc:  The view controller that will present the settings
	///   - action: The action to perform
	@MainActor
	public static func checkCameraAccess(_ vc: UIViewController, action: @escaping () -> Void) {
		switch AVCaptureDevice.authorizationStatus(for: .video) {
		case .denied:
			// "Denied, request permission from settings"
			presentSettings(vc, msg: NSLocalizedString("Camera access is denied", comment: ""))
		case .restricted:
			logger.warning("Restricted, device owner must approve")
		case .authorized:
			// "Authorized, proceed"
			DispatchQueue.main.async { action() }
		case .notDetermined:
			AVCaptureDevice.requestAccess(for: .video) { success in
				if success {
					DispatchQueue.main.async { action() }
				} else {
					logger.info("Permission denied")
				}
			}
		@unknown default:
			logger.info("Unknown authorization status")
		}
	}
	
	/// Present an alert controller with a message, and two actions, one to cancel, and one to go to the settings page.
	/// - Parameters:
	///   - vc: The view controller that will present the settings
	///   - msg: The message to show
	@MainActor
	public static func presentSettings(_ vc: UIViewController, msg: String) {
		let alertController = UIAlertController(title: NSLocalizedString("error", comment: ""), message: msg, preferredStyle: .alert)
		alertController.addAction(UIAlertAction(title: NSLocalizedString("cancel", comment: ""), style: .default))
		alertController.addAction(UIAlertAction(title: NSLocalizedString("settings", comment: ""), style: .cancel) { _ in
			if let url = URL(string: UIApplication.openSettingsURLString) {
				UIApplication.shared.open(url, options: [:], completionHandler: { _ in
					// Handle
				})
			}
		})
		vc.present(alertController, animated: true)
	}
	
	/// Finds the top view controller in the view hierarchy of the app. It is used to present a new view controller on top of any existing view controllers.
	@MainActor
	public static func getTopViewController(base: UIViewController? = UIApplication.shared.windows.first { $0.isKeyWindow }?.rootViewController) -> UIViewController? {
		if let nav = base as? UINavigationController {
			return getTopViewController(base: nav.visibleViewController)
		} else if let tab = base as? UITabBarController, let selected = tab.selectedViewController {
			return getTopViewController(base: selected)
		} else if let presented = base?.presentedViewController {
			return getTopViewController(base: presented)
		}
		return base
	}
	
#endif
	
	/// Get the common name (CN) from the certificate distringuished name (DN)
	public static func getCN(from dn: String) -> String {
		do {
			let regex = try NSRegularExpression(pattern: "CN=([^,]+)")
			if let match = regex.firstMatch(in: dn, range: NSRange(location: 0, length: dn.count)) {
				if let r = Range(match.range(at: 1), in: dn) {
					return String(dn[r])
				}
			}
			return dn
		} catch {
			return ""  // TODO: !!
		}
	}
	
}
