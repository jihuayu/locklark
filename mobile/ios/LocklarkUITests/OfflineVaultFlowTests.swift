import XCTest
import UIKit
import UniformTypeIdentifiers
import CryptoKit

final class OfflineVaultFlowTests: XCTestCase {
    private var factor = ""
    private var firstPassword = ""
    private var replacementPassword = ""
    private var username = ""
    private var canaries = [String]()
    private var manifestURL: URL?
    private let manifestRun = UUID().uuidString
    private var manifestComplete = false

    override func setUpWithError() throws {
        continueAfterFailure = false
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("LocklarkUITestEvidence", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        manifestURL = directory.appendingPathComponent("canaries.json")
        factor = record("ios-master-" + UUID().uuidString)
        firstPassword = record("ios-password-" + UUID().uuidString)
        replacementPassword = record("ios-edited-" + UUID().uuidString)
        username = record("ios-user-" + UUID().uuidString)
    }

    private func persistManifest() {
        guard let path = manifestURL else { XCTFail("private fixture manifest must have an owned location"); return }
        do {
            let value: [String: Any] = ["version": 1, "run_id": manifestRun,
                "test": "OfflineVaultFlowTests.testActualOfflineCreateUnlockEditRevealAndBackgroundLock",
                "complete": manifestComplete, "canaries": canaries]
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: path, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        } catch { XCTFail("private fixture manifest must be persisted") }
    }

    @discardableResult private func record(_ value: String) -> String {
        guard !value.isEmpty else { XCTFail("explicit fixture value must not be empty"); return value }
        if !canaries.contains(value) { canaries.append(value) }
        persistManifest()
        return value
    }

    // This oracle uses CryptoKit directly and never asks the vault for an
    // expected code. The seed bytes and resulting code stay in the runner.
    private func totp(_ seed: Data, counter: UInt64) -> String {
        var bigEndian = counter.bigEndian
        let message = Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)
        let digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: seed)))
        let offset = Int(digest[digest.count - 1] & 15)
        let number = (UInt32(digest[offset]) << 24 | UInt32(digest[offset + 1]) << 16 |
                      UInt32(digest[offset + 2]) << 8 | UInt32(digest[offset + 3])) & 0x7fffffff
        let raw = String(number % 1_000_000)
        return String(repeating: "0", count: 6 - raw.count) + raw
    }

    private func base32(_ bytes: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var result = [UInt8](), buffer: UInt32 = 0, bits = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte); bits += 8
            while bits >= 5 { bits -= 5; result.append(alphabet[Int((buffer >> bits) & 31)]) }
            buffer &= (UInt32(1) << bits) - 1
        }
        if bits > 0 { result.append(alphabet[Int((buffer << (5 - bits)) & 31)]) }
        return String(decoding: result, as: UTF8.self)
    }

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
        XCTAssertTrue(totp(Data("12345678901234567890".utf8), counter: 1) == "287082", "independent HMAC framing must match the RFC vector")
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
        record(key)
        let createButton = app.buttons["confirm-create"]
        XCTAssertFalse(createButton.isEnabled, "backup acknowledgement is mandatory")
        app.switches["backup-ack"].tap()
        createButton.tap()
        XCTAssertTrue(app.secureTextFields["unlock-password"].waitForExistence(timeout: 30), "creation must leave a locked actual database")
        unlock(app, key: key)
        app.buttons["add-login"].tap()
        app.textFields["login-title"].tap()
        app.textFields["login-title"].typeText("Offline fixture")
        paste(username, into: app.secureTextFields["login-username"], app: app)
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
        var random = SystemRandomNumberGenerator()
        let seed = Data((0..<20).map { _ in UInt8.random(in: 0...255, using: &random) })
        let encodedSeed = record(base32(seed))
        let period = 30
        let otpConfiguration = record("otpauth://totp/Fixture?secret=" + encodedSeed + "&period=" + String(period))
        paste(otpConfiguration, into: app.secureTextFields["edit-value"], app: app)
        app.buttons["save-edit"].tap()
        choose(app, title: "Offline fixture")
        while Int(Date().timeIntervalSince1970) % period > 8 { Thread.sleep(forTimeInterval: 0.2) }
        let before = Int(Date().timeIntervalSince1970)
        app.buttons["show-otp-code"].tap()
        let otp = app.staticTexts["revealed-value"]
        XCTAssertTrue(otp.waitForExistence(timeout: 15), "explicit OTP disclosure must complete")
        let code = record(otp.value as? String ?? "")
        let after = Int(Date().timeIntervalSince1970)
        XCTAssertTrue(code.utf8.count == 6 && code.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }, "OTP must contain only its supported digits")
        let firstCode = record(totp(seed, counter: UInt64(before / period)))
        let lastCode = record(totp(seed, counter: UInt64(after / period)))
        XCTAssertTrue(after >= before && after - before <= 15 && after / period - before / period <= 1,
                      "OTP observation must remain within its original bounded UTC window")
        XCTAssertTrue(code == firstCode || code == lastCode, "OTP must match independent CryptoKit HMAC-SHA1")
        app.buttons["add-login"].tap()
        app.textFields["login-title"].tap()
        app.textFields["login-title"].typeText("Generated fixture")
        app.switches["login-generate"].tap()
        app.buttons["save-login"].tap()
        choose(app, title: "Generated fixture")
        app.buttons["show-password"].tap()
        let generated = app.staticTexts["revealed-value"]
        XCTAssertTrue(generated.waitForExistence(timeout: 15), "generated password must require explicit display")
        let previous = record(generated.value as? String ?? "")
        XCTAssertTrue(previous.count == 24, "generated password must follow the requested length")
        app.buttons["regenerate-password"].tap()
        choose(app, title: "Generated fixture")
        app.buttons["show-password"].tap()
        XCTAssertTrue(generated.waitForExistence(timeout: 15), "regenerated password must require explicit display")
        let changed = record(generated.value as? String ?? "")
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
        manifestComplete = true
        persistManifest()
    }
}
