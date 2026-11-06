import XCTest
import LocklarkSecurityLogic
@testable import Locklark

final class CoreIntegrationTests: XCTestCase {
    func testActualGoCreateAndReopenKeepsDatabaseCompletelyProtected() throws {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("Locklark-Test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete])
        defer { try? FileManager.default.removeItem(at: directory) }
        try VaultFiles.protect(directory: directory)
        let path = directory.appendingPathComponent("real-core.ll").path
        let vault = try LLVault.open(path: path)
        defer { vault.requestLock(); vault.close() }
        var key = try LLVault.generateSecretKey()
        let keyText = LLVault.formatSecretKey(key)
        var password = Data("ios-integration-factor".utf8)
        defer { key.resetBytes(in: 0..<key.count); password.resetBytes(in: 0..<password.count) }
        try vault.create(password: password, secretKey: key)
        // Check the Go-created file before any post-create strengthening.
        try VaultFiles.verifyProtection(directory: directory)
        try VaultFiles.protect(directory: directory)
        var freshKey = try LLVault.parseSecretKey(keyText)
        var freshPassword = Data("ios-integration-factor".utf8)
        defer { freshKey.resetBytes(in: 0..<freshKey.count); freshPassword.resetBytes(in: 0..<freshPassword.count) }
        try vault.unlock(password: freshPassword, secretKey: freshKey)
        XCTAssertTrue(vault.isUnlocked(), "actual core must open the created vault")
        XCTAssertTrue(try vault.rows(query: "").isEmpty, "new actual vault must have an empty list")
        let storedTitle = "persisted\u{202e}\u{2066}\u{200d}"
        var username = Data("fixture-user".utf8), value = Data("fixture-password".utf8)
        defer { username.resetBytes(in: 0..<username.count); value.resetBytes(in: 0..<value.count) }
        _ = try vault.createLogin(title: storedTitle, url: "", username: username, password: value)
        let rows = try vault.rows(query: "persisted")
        XCTAssertTrue(rows.count == 1 && rows[0].title == storedTitle, "authenticated storage must preserve the imported title bytes")
        XCTAssertTrue(VisibleText.title(rows[0].title) == "persisted\\u{202e}\\u{2066}\\u{200d}", "native title display must expose formatting controls")
        try VaultFiles.verifyProtection(directory: directory)
    }
}
