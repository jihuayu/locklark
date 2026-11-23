import XCTest

final class ProtectionCapabilityDenialUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }

    func testActualAppKeepsCreationDisabledWhenProtectionIsUnavailable() {
        let app = XCUIApplication()
        app.launch()
        let create = app.buttons["create-vault"]
        XCTAssertTrue(create.waitForExistence(timeout: 15), "unavailable-capability app must remain on its locked native screen")
        let status = app.staticTexts["vault-status"]
        let refused = XCTNSPredicateExpectation(predicate: NSPredicate { _, _ in
            status.exists && status.label.contains("无法启用本机受保护存储")
        }, object: nil)
        XCTAssertEqual(XCTWaiter.wait(for: [refused], timeout: 15), .completed, "actual app must explicitly report protected-storage refusal")
        XCTAssertFalse(create.isEnabled, "actual app must never enable creation with unavailable protection")
        XCTAssertFalse(app.secureTextFields["unlock-password"].exists, "denial fixture must not open or create a vault")
        XCTAssertFalse(app.buttons["add-login"].exists, "denial fixture must not expose an unlocked session")
    }
}
