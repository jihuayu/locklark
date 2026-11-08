import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

/// Production peer check. The UID is pinned to the current user, but UID alone
/// is never accepted: SecCode must validate a fixed requirement naming the
/// configured Team ID and the exact Safari web extension bundle identifier.
enum PeerVerifier {
    static func credentials(
        fd: Int32,
        identity: ConfiguredIdentity
    ) -> PeerCredentials? {
        guard let peer = SocketSupport.peerProcess(fd: fd) else { return nil }
        let currentUID = UInt32(getuid())
        guard peer.uid == currentUID else {
            return PeerCredentials(
                pid: peer.pid,
                uid: peer.uid,
                teamID: nil,
                bundleID: nil,
                signatureValid: false
            )
        }
        var code: SecCode?
        let attributes = [
            kSecGuestAttributePid as String: NSNumber(value: peer.pid)
        ] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else {
            return PeerCredentials(
                pid: peer.pid,
                uid: peer.uid,
                teamID: nil,
                bundleID: nil,
                signatureValid: false
            )
        }
        var signatureValid = false
        if let requirementText = PeerPolicy.signingRequirement(
            teamID: identity.teamID,
            extensionBundleID: identity.extensionBundleID
        ) {
            var requirement: SecRequirement?
            if SecRequirementCreateWithString(
                requirementText as CFString,
                [],
                &requirement
            ) == errSecSuccess, let requirement {
                signatureValid = SecCodeCheckValidity(code, [], requirement) ==
                    errSecSuccess
            }
        }
        var teamID: String?
        var bundleID: String?
        var signingInfo: CFDictionary?
        if SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInfo
        ) == errSecSuccess,
           let info = signingInfo as? [String: Any] {
            teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
            bundleID = info[kSecCodeInfoIdentifier as String] as? String
        }
        return PeerCredentials(
            pid: peer.pid,
            uid: peer.uid,
            teamID: teamID,
            bundleID: bundleID,
            signatureValid: signatureValid
        )
    }

    static func accepts(fd: Int32, identity: ConfiguredIdentity) -> Bool {
        guard let peer = credentials(fd: fd, identity: identity) else {
            return false
        }
        return PeerPolicy.accepts(
            peer: peer,
            expectedUID: UInt32(getuid()),
            expectedTeamID: identity.teamID,
            expectedExtensionBundleID: identity.extensionBundleID
        )
    }
}
