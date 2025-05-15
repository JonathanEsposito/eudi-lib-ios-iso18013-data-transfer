//
//  DeviceRequest+UserRequestInfo.swift
//  MdocDataTransfer18013
//
//  Created by Jonathan Esposito on 13/05/2025.
//

import Foundation
import MdocDataModel18013

extension DeviceRequest {
	
	var userRequestInfo: UserRequestInfo {
		// TODO: Weird docType specific stuff about moreThan2AgeOverElementIdentifiers currently ignored
		let requestItems = docRequests.flatMap(\.itemsRequest.requestItems).reduce(into: RequestItems()) { $0[$1.key] = $1.value }
		let documentFormats = docRequests.flatMap(\.itemsRequest.docType).reduce(into: [String: DocDataFormat]()) { $0[$1] = .cbor }
		
		return UserRequestInfo(docDataFormats: documentFormats, itemsRequested: requestItems)
	}
	
}