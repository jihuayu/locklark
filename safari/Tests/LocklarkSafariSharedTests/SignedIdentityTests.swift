import XCTest
@testable import LocklarkSafariShared

final class SignedIdentityTests: XCTestCase {
    private func info(
        team: String = "ABCDE12345",
        group: String = ConfiguredIdentity.fixedAppGroupID,
        app: String = ConfiguredIdentity.fixedContainingAppBundleID,
        extensionID: String = ConfiguredIdentity.fixedExtensionBundleID
    ) -> [String: Any] {
        [
            InfoKeys.teamID: team,
            InfoKeys.appGroupID: group,
            InfoKeys.containingAppBundleID: app,
            InfoKeys.extensionBundleID: extensionID,
        ]
    }

    func testFixedIdentityLoads() throws {
        let identity = try ConfiguredIdentity.from(infoDictionary: info())
        XCTAssertEqual(identity.appGroupID, ConfiguredIdentity.fixedAppGroupID)
        XCTAssertEqual(
            identity.extensionBundleID,
            ConfiguredIdentity.fixedExtensionBundleID
        )
    }

    func testBlankAndPlaceholderValuesFailClosed() {
        for value in [
            "",
            "   ",
            "$(LOCKLARK_TEAM_ID)",
            "YOUR_TEAM_ID",
            "TEAM_ID_HERE",
            "REPLACE_ME",
            "CHANGEME",
            "UNSIGNEDCI0",
        ] {
            XCTAssertThrowsError(
                try ConfiguredIdentity.from(
                    infoDictionary: info(team: value)
                )
            )
        }
    }

    func testMismatchedBundleSuffixFails() {
        XCTAssertThrowsError(
            try ConfiguredIdentity.from(
                infoDictionary: info(
                    extensionID: "org.locklark.browser.safari.Other"
                )
            )
        )
    }

    func testNonFixedIdentitiesFail() {
        let app = "org.example.browser"
        XCTAssertThrowsError(
            try ConfiguredIdentity.from(
                infoDictionary: info(
                    app: app,
                    extensionID: app + ".Extension"
                )
            )
        )
    }

    func testValidationRules() {
        XCTAssertTrue(ConfiguredIdentity.isValidTeamID("ABCDE12345"))
        XCTAssertFalse(ConfiguredIdentity.isValidTeamID("ABCDE1234"))
        XCTAssertFalse(ConfiguredIdentity.isValidTeamID("abcde12345"))
        XCTAssertTrue(
            ConfiguredIdentity.isValidAppGroupID(
                ConfiguredIdentity.fixedAppGroupID
            )
        )
        XCTAssertFalse(ConfiguredIdentity.isValidAppGroupID("org.example"))
        XCTAssertFalse(
            ConfiguredIdentity.isValidAppGroupID("group..bad")
        )
    }
}
