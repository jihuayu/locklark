import XCTest
import UIKit
import UniformTypeIdentifiers

final class OfflineVaultFlowTests: XCTestCase {
    private let factor = "ios-ui-synthetic-factor"
    private let firstPassword = "ios-ui-first-password"
    private let replacementPassword = "ios-ui-replacement-password"

    override func setUpWithError() throws { continueAfterFailure = false }

    private func paste(_ text: String, into element: XCUIElement, app: XCUIApplication) {
        XCTAssertTrue(element.waitForExistence(timeout: 10), "native input must exist")
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(30)])
        defer { UIPasteboard.general.items = [] }
        element.tap()
        element.press(forDuration: 1.1)
        let predicate = NSPredicate(format: "label IN %@", ["Paste", "粘贴"])
        let paste = app.menuItems.matching(predicate).firstMatch
        if paste.waitForExistence(timeout: 3) { paste.tap() }
        else {
            let button = app.buttons.matching(predicate).firstMatch
            XCTAssertTrue(button.waitForExistence(timeout: 3), "system paste action must be available")
            button.tap()
        }
    }

    private func unlock(_ app: XCUIApplication, key: String) {
        paste(factor, into: app.secureTextFields["unlock-password"], app: app)
        paste(key, into: app.secureTextFields["unlock-secret-key"], app: app)
        app.buttons["unlock-vault"].tap()
        XCTAssertTrue(app.buttons["add-login"].waitForExistence(timeout: 30), "real vault list must open")
    }

    private func choose(_ app: XCUIApplication, title: String) {
        let row = app.buttons["row-title-" + title]
        if !row.isHittable { app.swipeUp() }
        XCTAssertTrue(row.waitForExistence(timeout: 10), "saved metadata row must exist")
        row.tap()
    }

    private func assertPassword(_ app: XCUIApplication, expected: String) {
        app.buttons["show-password"].tap()
        let value = app.staticTexts["revealed-value"]
        XCTAssertTrue(value.waitForExistence(timeout: 15), "explicit disclosure must complete")
        XCTAssertTrue((value.value as? String) == expected, "explicit disclosure must contain the selected value")
    }

    func testActualOfflineCreateUnlockEditRevealAndBackgroundLock() {
        let app = XCUIApplication()
        app.launch()
        let create = app.buttons["create-vault"]
        XCTAssertTrue(create.waitForExistence(timeout: 15), "fresh sandbox must offer real vault creation")
        create.tap()
        paste(factor, into: app.secureTextFields["create-password"], app: app)
        paste(factor, into: app.secureTextFields["create-confirmation"], app: app)
        app.buttons["generate-secret-key"].tap()
        let keyElement = app.staticTexts["create-secret-key"]
        XCTAssertTrue(keyElement.waitForExistence(timeout: 10), "generated account key must be explicitly shown")
        guard let key = keyElement.value as? String, key.hasPrefix("LL1-") else { XCTFail("generated account key must have the native format"); return }
        let createButton = app.buttons["confirm-create"]
        XCTAssertFalse(createButton.isEnabled, "backup acknowledgement is mandatory")
        app.switches["backup-ack"].tap()
        createButton.tap()
        XCTAssertTrue(app.secureTextFields["unlock-password"].waitForExistence(timeout: 30), "creation must leave a locked actual database")
        unlock(app, key: key)
        app.buttons["add-login"].tap()
        app.textFields["login-title"].tap()
        app.textFields["login-title"].typeText("Offline fixture")
        paste("native-fixture-user", into: app.secureTextFields["login-username"], app: app)
        paste(firstPassword, into: app.secureTextFields["login-password"], app: app)
        app.buttons["save-login"].tap()
        choose(app, title: "Offline fixture")
        assertPassword(app, expected: firstPassword)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.secureTextFields["unlock-password"].waitForExistence(timeout: 10), "backgrounding must lock")
        XCTAssertFalse(app.staticTexts["revealed-value"].exists, "backgrounding must clear disclosed text")
        app.buttons["system-unlock"].tap()
        XCTAssertTrue(app.secureTextFields["unlock-password"].exists, "quick unlock must not auto-enable after full-factor unlock")
        unlock(app, key: key)
        choose(app, title: "Offline fixture")
        app.buttons["edit-fields"].tap()
        app.buttons["edit-password"].tap()
        paste(replacementPassword, into: app.secureTextFields["edit-value"], app: app)
        app.buttons["save-edit"].tap()
        choose(app, title: "Offline fixture")
        assertPassword(app, expected: replacementPassword)
        app.buttons["hide-value"].tap()
        app.buttons["edit-fields"].tap()
        app.buttons["edit-otp"].tap()
        // Synthetic base32 seed is constructed without ever putting it in a
        // launch argument, assertion diff or typeText action log.
        let base32 = String(repeating: "CMJR", count: 8)
        var period = 3600
        let now = Int(Date().timeIntervalSince1970)
        while now % period > period - 30 { period -= 1 }
        paste("otpauth://totp/Fixture?secret=" + base32 + "&period=" + String(period), into: app.secureTextFields["edit-value"], app: app)
        app.buttons["save-edit"].tap()
        choose(app, title: "Offline fixture")
        app.buttons["show-otp-code"].tap()
        let otp = app.staticTexts["revealed-value"]
        XCTAssertTrue(otp.waitForExistence(timeout: 15), "explicit OTP disclosure must complete")
        let code = otp.value as? String ?? ""
        XCTAssertTrue(code.utf8.count == 6 && code.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }, "OTP must contain only its supported digits")
        app.buttons["add-login"].tap()
        app.textFields["login-title"].tap()
        app.textFields["login-title"].typeText("Generated fixture")
        app.switches["login-generate"].tap()
        app.buttons["save-login"].tap()
        choose(app, title: "Generated fixture")
        app.buttons["show-password"].tap()
        let generated = app.staticTexts["revealed-value"]
        XCTAssertTrue(generated.waitForExistence(timeout: 15), "generated password must require explicit display")
        let previous = generated.value as? String ?? ""
        XCTAssertTrue(previous.count == 24, "generated password must follow the requested length")
        app.buttons["regenerate-password"].tap()
        choose(app, title: "Generated fixture")
        app.buttons["show-password"].tap()
        XCTAssertTrue(generated.waitForExistence(timeout: 15), "regenerated password must require explicit display")
        let changed = generated.value as? String ?? ""
        XCTAssertTrue(changed.count == 24 && changed != previous, "regeneration must persist a new value")
        app.textFields["title-search"].tap()
        app.textFields["title-search"].typeText("Offline")
        app.buttons["search-submit"].tap()
        XCTAssertTrue(app.buttons["row-title-Offline fixture"].waitForExistence(timeout: 10), "title search must find the existing login")
        XCTAssertFalse(app.buttons["row-title-Generated fixture"].exists, "title search must filter unrelated metadata")
        app.buttons["lock-vault"].tap()
        XCTAssertTrue(app.secureTextFields["unlock-password"].waitForExistence(timeout: 10), "manual lock must clear the session")
        unlock(app, key: key)
        choose(app, title: "Offline fixture")
        assertPassword(app, expected: replacementPassword)
    }
}
