import XCTest
import Security
@testable import Locklark

private final class RecordingKeychainClient: KeychainClient {
    var added: [[String: Any]] = []
    var copied: [[String: Any]] = []
    var deleted: [[String: Any]] = []
    var addStatus = errSecSuccess
    var loadStatus = errSecUserCanceled
    var deleteStatus = errSecItemNotFound

    func add(_ attributes: [String: Any]) -> OSStatus { added.append(attributes); return addStatus }
    func copy(_ query: [String: Any], result: inout CFTypeRef?) -> OSStatus { copied.append(query); return loadStatus }
    func delete(_ query: [String: Any]) -> OSStatus { deleted.append(query); return deleteStatus }
}

final class PlatformProtectionTests: XCTestCase {
    func testCapsuleUsesDeviceOnlyUserPresenceAndCannotSynchronize() throws {
        let client = RecordingKeychainClient()
        var requestedAccessibility: String?
        var requestedFlags: SecAccessControlCreateFlags = []
        let store = CapsuleKeychain(client: client, makeAccessControl: { accessibility, flags in
            requestedAccessibility = accessibility as String
            requestedFlags = flags
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil, accessibility, flags, &error) else { throw PlatformProtectionError.unavailable }
            return control
        })
        try store.store(id: "synthetic-capsule", value: Data([1, 2, 3]))
        XCTAssertEqual(client.added.count, 1)
        let item = client.added[0]
        XCTAssertEqual(item[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(item[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertNotNil(item[kSecAttrAccessControl as String])
        XCTAssertEqual(requestedAccessibility, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
        XCTAssertTrue(requestedFlags.contains(.userPresence), "every capsule read requires OS user presence")
        XCTAssertNil(item[kSecAttrAccessible as String], "accessibility is bound inside SecAccessControl")
    }

    func testCancelledAuthenticationDoesNotReturnOrCreateCapsule() {
        let client = RecordingKeychainClient()
        let store = CapsuleKeychain(client: client)
        XCTAssertThrowsError(try store.load(id: "synthetic-capsule"))
        XCTAssertEqual(client.copied.count, 1)
        XCTAssertEqual(client.added.count, 0)
        XCTAssertEqual(client.deleted.count, 0)
        XCTAssertNotNil(client.copied[0][kSecUseAuthenticationContext as String])
    }

    func testUnavailableKeychainHasNoLessProtectedRetry() {
        let client = RecordingKeychainClient()
        client.addStatus = errSecNotAvailable
        let store = CapsuleKeychain(client: client)
        XCTAssertThrowsError(try store.store(id: "synthetic-capsule", value: Data([1])))
        XCTAssertEqual(client.added.count, 1)
        XCTAssertNotNil(client.added[0][kSecAttrAccessControl as String])
    }

    func testCancelledAdapterCannotStartADelayedAuthentication() {
        let client = RecordingKeychainClient()
        let store = CapsuleKeychain(client: client)
        store.cancelAuthentication()
        XCTAssertThrowsError(try store.load(id: "synthetic-capsule"))
        XCTAssertTrue(client.copied.isEmpty, "a cancelled native request must not open a new OS prompt")
        XCTAssertThrowsError(try store.store(id: "synthetic-capsule", value: Data([1])))
        XCTAssertTrue(client.added.isEmpty, "cancelled enrollment must not start OS storage")
        XCTAssertNoThrow(try store.delete(id: "synthetic-capsule"), "stale enrollment cleanup must remain available")
    }

    func testVaultAndExistingSidecarsAreExcludedAndCompletelyProtected() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        for name in ["personal.ll", "personal.ll-wal", ".locklark-create"] {
            XCTAssertTrue(FileManager.default.createFile(atPath: directory.appendingPathComponent(name).path, contents: Data([1])))
        }
        try VaultFiles.protect(directory: directory)
        for url in [directory] + (try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) {
            XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            XCTAssertEqual(attributes[.protectionKey] as? FileProtectionType, .complete)
        }
    }

    func testVaultProtectionRefusesSymlinkSidecar() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("sidecar"), withDestinationURL: URL(fileURLWithPath: "/tmp"))
        XCTAssertThrowsError(try VaultFiles.protect(directory: directory))
    }
}
