import XCTest
import Security
import LocalAuthentication
import LocklarkSecurityLogic
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
        let authorization = SystemAuthenticationAuthorization(context: LAContext(), authenticatedAt: .now)
        let store = CapsuleKeychain(client: client, authorization: authorization)
        XCTAssertThrowsError(try store.load(id: "synthetic-capsule"))
        XCTAssertEqual(client.copied.count, 1)
        XCTAssertEqual(client.added.count, 0)
        XCTAssertEqual(client.deleted.count, 0)
        XCTAssertNotNil(client.copied[0][kSecUseAuthenticationContext as String])
        XCTAssertEqual(client.copied[0][kSecUseAuthenticationUI as String] as? String, kSecUseAuthenticationUIFail as String)
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

    func testLoadRequiresOwnedPreauthenticationAndNeverPromptsItself() {
        let client = RecordingKeychainClient()
        let store = CapsuleKeychain(client: client)
        XCTAssertThrowsError(try store.load(id: "synthetic-capsule"))
        XCTAssertTrue(client.copied.isEmpty, "unowned OS authentication must not be started by a data load")
    }

    func testCapsulePresenceReadsOnlyMetadataWithoutPrompting() throws {
        let client = RecordingKeychainClient()
        client.loadStatus = errSecItemNotFound
        let store = CapsuleKeychain(client: client)
        XCTAssertFalse(try store.hasCapsule())
        XCTAssertEqual(client.copied[0][kSecReturnAttributes as String] as? Bool, true)
        XCTAssertNil(client.copied[0][kSecReturnData as String])
        XCTAssertEqual(client.copied[0][kSecUseAuthenticationUI as String] as? String, kSecUseAuthenticationUIFail as String)
    }

    func testAuthorizedContextIsSingleUseAndCannotBeRenewedAfterExpiry() throws {
        let authorization = SystemAuthenticationAuthorization(context: LAContext(), authenticatedAt: .now)
        _ = try authorization.take()
        XCTAssertThrowsError(try authorization.take())
        let expired = SystemAuthenticationAuthorization(context: LAContext(), authenticatedAt: ContinuousClock.now.advanced(by: .seconds(-11)))
        XCTAssertThrowsError(try expired.take())
        XCTAssertThrowsError(try expired.take())
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
            XCTAssertTrue(ProtectionAttribute.isComplete(attributes[.protectionKey]), "actual Foundation protection attribute must exactly equal complete")
        }
    }

    func testVaultProtectionRefusesSymlinkSidecar() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("sidecar"), withDestinationURL: URL(fileURLWithPath: "/tmp"))
        XCTAssertThrowsError(try VaultFiles.protect(directory: directory))
    }

    func testFoundationRawProtectionStringIsAcceptedWithoutAcceptingWeakerValues() {
        let raw: Any = FileProtectionType.complete.rawValue as NSString
        XCTAssertTrue(ProtectionAttribute.isComplete(raw), "Foundation raw NSString must preserve exact complete-protection semantics")
        XCTAssertFalse(ProtectionAttribute.isComplete(FileProtectionType.completeUnlessOpen.rawValue))
        XCTAssertFalse(ProtectionAttribute.isComplete(nil))
    }
}
