import Foundation

/// The parts of a peer identity that the pure policy needs. Production code
/// fills them from SecCode; unit tests can construct them directly.
public struct PeerCredentials: Equatable {
    public let pid: Int32
    public let uid: UInt32
    public let teamID: String?
    public let bundleID: String?
    public let signatureValid: Bool

    public init(
        pid: Int32,
        uid: UInt32,
        teamID: String?,
        bundleID: String?,
        signatureValid: Bool
    ) {
        self.pid = pid
        self.uid = uid
        self.teamID = teamID
        self.bundleID = bundleID
        self.signatureValid = signatureValid
    }
}

/// A peer is accepted only when the socket UID matches, the code signature is
/// valid, the Team ID matches the configured Team ID and the bundle identifier
/// is exactly the configured Safari web extension. A UID match alone is never
/// sufficient because any process of the same user could connect.
public enum PeerPolicy {
    public static func accepts(
        peer: PeerCredentials,
        expectedUID: UInt32,
        expectedTeamID: String,
        expectedExtensionBundleID: String
    ) -> Bool {
        guard !ConfiguredIdentity.isPlaceholder(expectedTeamID),
              ConfiguredIdentity.isValidTeamID(expectedTeamID)
        else { return false }
        guard !ConfiguredIdentity.isPlaceholder(expectedExtensionBundleID),
              ConfiguredIdentity.isValidBundleID(expectedExtensionBundleID)
        else { return false }
        guard peer.uid == expectedUID else { return false }
        guard peer.signatureValid else { return false }
        guard let teamID = peer.teamID,
              !ConfiguredIdentity.isPlaceholder(teamID),
              teamID == expectedTeamID
        else { return false }
        guard let bundleID = peer.bundleID,
              bundleID == expectedExtensionBundleID
        else { return false }
        return true
    }

    /// Fixed requirement text. Neither the Team ID nor the bundle identifier
    /// can come from JavaScript, argv, an environment file or an IPC frame.
    public static func signingRequirement(
        teamID: String,
        extensionBundleID: String
    ) -> String? {
        guard !ConfiguredIdentity.isPlaceholder(teamID),
              ConfiguredIdentity.isValidTeamID(teamID),
              ConfiguredIdentity.isValidBundleID(extensionBundleID)
        else { return nil }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(extensionBundleID)\""
    }
}
