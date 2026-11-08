import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

/// Production peer check. The kernel UID is pinned to the current user, but UID
/// alone is never accepted: SecCode must validate a fixed requirement naming
/// the configured Team ID and the exact Safari web extension bundle identifier.
///
/// The guest is always looked up from the kernel *audit token* of the connected
/// socket (`kSecGuestAttributeAudit`), never from a numeric PID. A PID can be
/// re-resolved to a different process between the check and the lookup (the
/// PID-reuse TOCTOU), while the audit token names one process instance: it
/// carries the pidversion that the kernel bumps on every reuse.
enum PeerVerifier {
    static func credentials(
        fd: Int32,
        identity: ConfiguredIdentity
    ) -> PeerCredentials? {
        guard let peer = SocketSupport.peerAuditToken(fd: fd) else { return nil }
        guard peer.uid == UInt32(getuid()) else {
            return rejected(peer)
        }
        var code: SecCode?
        // Opaque audit token only: no numeric PID fallback exists, so the
        // SecCode lookup cannot be steered to another process.
        let attributes = [
            kSecGuestAttributeAudit as String: peer.token
        ] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else {
            return rejected(peer)
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
                // Dynamic validation of the running guest stays the gate.
                signatureValid = SecCodeCheckValidity(code, [], requirement) ==
                    errSecSuccess
            }
        }
        var teamID: String?
        var bundleID: String?
        // SecCodeCopySigningInformation needs the static code, not the live
        // SecCode. Derive the static code from the same guest; if that fails
        // both IDs stay nil and PeerPolicy refuses the peer.
        var staticCode: SecStaticCode?
        if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
           let staticCode {
            var signingInfo: CFDictionary?
            if SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &signingInfo
            ) == errSecSuccess,
               let info = signingInfo as? [String: Any] {
                teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
                bundleID = info[kSecCodeInfoIdentifier as String] as? String
            }
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

    private static func rejected(
        _ peer: SocketSupport.PeerAuditToken
    ) -> PeerCredentials {
        PeerCredentials(
            pid: peer.pid,
            uid: peer.uid,
            teamID: nil,
            bundleID: nil,
            signatureValid: false
        )
    }
}
