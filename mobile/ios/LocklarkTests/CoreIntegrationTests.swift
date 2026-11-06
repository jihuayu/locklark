import XCTest
import LocklarkSecurityLogic
@testable import Locklark

final class CoreIntegrationTests: XCTestCase {
    private enum Phase: String {
        case open = "core-phase-open"
        case create = "core-phase-create"
        case defaultProtection = "core-phase-default-protection"
        case strengthenProtection = "core-phase-strengthen-protection"
        case unlock = "core-phase-unlock"
        case list = "core-phase-list"
        case createLogin = "core-phase-create-login"
        case search = "core-phase-search"
        case reveal = "core-phase-reveal"
        case take = "core-phase-take"
    }
    private struct PhaseFailure: Error {}

    private func phase<T>(_ phase: Phase, file: StaticString = #filePath, line: UInt = #line, _ action: () throws -> T) throws -> T {
        do { return try action() }
        catch { XCTFail(phase.rawValue, file: file, line: line); throw PhaseFailure() }
    }

    func testActualGoCreateAndReopenKeepsDatabaseCompletelyProtected() throws {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("Locklark-Test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete])
        defer { try? FileManager.default.removeItem(at: directory) }
        try phase(.strengthenProtection) { try VaultFiles.protect(directory: directory) }
        let path = directory.appendingPathComponent("real-core.ll").path
        let vault = try phase(.open) { try LLVault.open(path: path) }
        defer { vault.requestLock(); vault.close() }
        var key = try LLVault.generateSecretKey()
        let keyText = LLVault.formatSecretKey(key)
        var password = Data("ios-integration-factor".utf8)
        defer { key.resetBytes(in: 0..<key.count); password.resetBytes(in: 0..<password.count) }
        try phase(.create) { try vault.create(password: password, secretKey: key) }
        // Check the Go-created file before any post-create strengthening.
        try phase(.defaultProtection) { try VaultFiles.verifyProtection(directory: directory) }
        try phase(.strengthenProtection) { try VaultFiles.protect(directory: directory) }
        var freshKey = try LLVault.parseSecretKey(keyText)
        var freshPassword = Data("ios-integration-factor".utf8)
        defer { freshKey.resetBytes(in: 0..<freshKey.count); freshPassword.resetBytes(in: 0..<freshPassword.count) }
        try phase(.unlock) { try vault.unlock(password: freshPassword, secretKey: freshKey) }
        XCTAssertTrue(vault.isUnlocked(), "actual core must open the created vault")
        XCTAssertTrue(try phase(.list) { try vault.rows(query: "").isEmpty }, "new actual vault must have an empty list")
        let storedTitle = "persisted\u{202e}\u{2066}\u{200d}"
        var username = Data("fixture-user".utf8), value = Data("fixture-password".utf8)
        defer { username.resetBytes(in: 0..<username.count); value.resetBytes(in: 0..<value.count) }
        _ = try phase(.createLogin) { try vault.createLogin(title: storedTitle, url: "", username: username, password: value) }
        let rows = try phase(.search) { try vault.rows(query: "persisted") }
        XCTAssertTrue(rows.count == 1 && rows[0].title == storedTitle, "authenticated storage must preserve the imported title bytes")
        XCTAssertTrue(VisibleText.title(rows[0].title) == "persisted\\u{202e}\\u{2066}\\u{200d}", "native title display must expose formatting controls")
        let emptyNotes = try phase(.reveal) { try vault.reveal(id: rows[0].identifier, revision: rows[0].revision, field: "notes") }
        defer { emptyNotes.clear() }
        let empty = try phase(.take) { try emptyNotes.take() }
        defer { empty.clear() }
        XCTAssertTrue(empty.data.length == 0, "successful empty disclosure must survive the gomobile nil-data bridge")
        try VaultFiles.verifyProtection(directory: directory)
    }

    func testQueuedUnlockCreateAndEditAreCancelledBeforeActualGoEntry() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete])
        defer { try? FileManager.default.removeItem(at: directory) }
        let keyText = LLVault.formatSecretKey(try LLVault.generateSecretKey())
        for kind in ["unlock", "create", "edit"] {
            let url = directory.appendingPathComponent(kind + ".ll")
            let vault = try LLVault.open(path: url.path)
            defer { vault.requestLock(); vault.close() }
            var row: LLRow?
            if kind != "create" {
                try vault.create(password: Data("queued-fixture-factor".utf8), secretKey: LLVault.parseSecretKey(keyText))
                if kind == "edit" {
                    try vault.unlock(password: Data("queued-fixture-factor".utf8), secretKey: LLVault.parseSecretKey(keyText))
                    _ = try vault.createLogin(title: "Queued fixture", url: "", username: Data(), password: Data("before".utf8))
                    row = try vault.rows(query: "").first
                }
            }
            let before = kind == "create" ? nil : try Data(contentsOf: url)
            let password = NativeSecretBuffer("queued-fixture-factor")
            let key = NativeSecretBuffer(data: try LLVault.parseSecretKey(keyText))
            let replacement = NativeSecretBuffer("after")
            let queue = DispatchQueue(label: "queued-native-" + kind)
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            queue.async { entered.signal(); release.wait() }
            XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
            let scope = CancellationScope(), ticket = scope.ticket()
            let captured = try vault.captureOperation()
            var calls = 0
            queue.async {
                do {
                    try ticket.run(cleanup: { password.clear(); key.clear(); replacement.clear() }) {
                        calls += 1
                        if kind == "create" { try captured.create(password: password.data, secretKey: key.data) }
                        else if kind == "unlock" { try captured.unlock(password: password.data, secretKey: key.data) }
                        else if let row { _ = try captured.edit(id: row.identifier, revision: row.revision, field: "password", value: replacement.data) }
                    }
                } catch {}
                done.signal()
            }
            scope.invalidate()
            vault.requestLock()
            release.signal()
            XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
            XCTAssertTrue(calls == 0, "cancelled queued operation must not enter real Go code")
            XCTAssertTrue(password.data.allSatisfy { $0 == 0 } && key.data.allSatisfy { $0 == 0 } && replacement.data.allSatisfy { $0 == 0 }, "cancelled captured factors must be cleared")
            if let before { XCTAssertTrue(try Data(contentsOf: url) == before, "cancelled queued operation must not change the authenticated database") }
            else { XCTAssertFalse(FileManager.default.fileExists(atPath: url.path), "cancelled queued creation must leave no database") }
            XCTAssertFalse(vault.isUnlocked(), "cancelled queued unlock must remain locked")
        }
    }

    func testGoCapturedEpochClosesNativePreflightToCallGap() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("never-created.ll").path
        let base = try LLVault.open(path: path)
        defer { base.requestLock(); base.close() }
        let view = try base.captureOperation()
        let password = NativeSecretBuffer("gap-fixture-factor")
        let key = NativeSecretBuffer(data: try LLVault.generateSecretKey())
        let scope = CancellationScope(), ticket = scope.ticket()
        let passedPreflight = DispatchSemaphore(value: 0), call = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        var refused = false
        DispatchQueue(label: "native-preflight-gap").async {
            do {
                try ticket.run(cleanup: { password.clear(); key.clear() }) {
                    passedPreflight.signal()
                    call.wait()
                    try view.create(password: password.data, secretKey: key.data)
                }
            } catch { refused = true }
            done.signal()
        }
        XCTAssertEqual(passedPreflight.wait(timeout: .now() + 5), .success)
        scope.invalidate()
        base.requestLock()
        call.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(refused, "Go-issued expected epoch must reject a call after native preflight")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path), "preflight-to-call cancellation must leave no database")
        XCTAssertTrue(password.data.allSatisfy { $0 == 0 } && key.data.allSatisfy { $0 == 0 }, "gap rejection must still wipe captured factors")
    }
}
