import Foundation
import MdocDataModel18013
import MdocSecurity18013

public struct InitializeTransferData: Sendable {

	public init(trustedCertificates: [Data], deviceAuthMethod: String) {
        self.trustedCertificates = trustedCertificates
        self.deviceAuthMethod = deviceAuthMethod
    }
	
    /// trusted certificates
    public let trustedCertificates: [Data]
    /// device auth method
    public let deviceAuthMethod: String

    public func toInitializeTransferInfo() -> InitializeTransferInfo {
        let iaca = trustedCertificates.map { SecCertificateCreateWithData(nil, $0 as CFData)! }
        let deviceAuthMethod = DeviceAuthMethod(rawValue: deviceAuthMethod) ?? .deviceMac
			return InitializeTransferInfo(iaca: iaca, deviceAuthMethod: deviceAuthMethod)
    }
}

public struct InitializeTransferInfo {
    /// trusted certificates
	public let iaca: [SecCertificate]
	/// device auth method
	public let deviceAuthMethod: DeviceAuthMethod
}
