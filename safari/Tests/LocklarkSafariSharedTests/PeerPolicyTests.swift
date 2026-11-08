import XCTest
@testable import LocklarkSafariShared

final class PeerPolicyTests: XCTestCase {
    private let team = "ABCDE12345"
    private let extensionID = ConfiguredIdentity.fixedExtensionBundleID
    private let uid: UInt32 = 501

    private func peer(
        uid: UInt32 = 501,
        teamID: String? = "ABCDE12345",
        bundleID: String? = ConfiguredIdentity.fixedExtensionBundleID,
        signatureValid: Bool = true
    ) -> PeerCredentials {
        PeerCredentials(
            pid: 700,
            uid: uid,
            teamID: teamID,
            bundleID: bundleID,
            signatureValid: signatureValid
        )
    }

    func testAcceptsExactSignedExtension() {
        XCTAssertTrue(
            PeerPolicy.accepts(
                peer: peer(),
                expectedUID: uid,
                expectedTeamID: team,
                expectedExtensionBundleID: extensionID
            )
        )
    }

    func testUidAloneIsNeverEnough() {
        XCTAssertFalse(
            PeerPolicy.accepts(
                peer: peer(teamID: nil, bundleID: nil, signatureValid: false),
                expectedUID: uid,
                expectedTeamID: team,
                expectedExtensionBundleID: extensionID
            )
        )
        XCTAssertFalse(
            PeerPolicy.accepts(
                peer: peer(teamID: nil, bundleID: nil, signatureValid: true),
                expectedUID: uid,
                expectedTeamID: team,
                expectedExtensionBundleID: extensionID
            )
        )
    }

    func testRejectsWrongUidTeamBundleOrSignature() {
        let cases = [
            peer(uid: 502),
            peer(teamID: "ZZZZZ99999"),
            peer(bundleID: "org.locklark.browser.safari"),
            peer(signatureValid: false),
        ]
        for candidate in cases {
            XCTAssertFalse(
                PeerPolicy.accepts(
                    peer: candidate,
                    expectedUID: uid,
                    expectedTeamID: team,
                    expectedExtensionBundleID: extensionID
                )
            )
        }
    }

    func testRejectsPlaceholderExpectations() {
        XCTAssertFalse(
            PeerPolicy.accepts(
                peer: peer(),
                expectedUID: uid,
                expectedTeamID: "YOUR_TEAM_ID",
                expectedExtensionBundleID: extensionID
            )
        )
        XCTAssertNil(
            PeerPolicy.signingRequirement(
                teamID: "YOUR_TEAM_ID",
                extensionBundleID: extensionID
            )
        )
    }

    func testSigningRequirementPinsTeamAndExactBundle() throws {
        let requirement = try XCTUnwrap(
            PeerPolicy.signingRequirement(
                teamID: team,
                extensionBundleID: extensionID
            )
        )
        XCTAssertTrue(requirement.contains(team))
        XCTAssertTrue(requirement.contains(extensionID))
        XCTAssertTrue(requirement.contains("anchor apple generic"))
    }
}
