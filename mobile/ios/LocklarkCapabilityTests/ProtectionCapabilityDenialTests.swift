import Foundation
import XCTest
@testable import Locklark

// Selected only by the explicitly negative simulator scheme. It is never part
// of the original signed-device full-positive scheme.
final class ProtectionCapabilityDenialTests: XCTestCase {
    func testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation() throws {
        let manager = FileManager.default
        let support = try manager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let personal = support.appendingPathComponent("Locklark/personal.ll")
        XCTAssertFalse(manager.fileExists(atPath: personal.path), "negative fixture must not contain a personal vault")
        let directory = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete.rawValue])
        defer { try? manager.removeItem(at: directory) }
        var file = directory.appendingPathComponent("public-fixture")
        XCTAssertTrue(manager.createFile(atPath: file.path, contents: Data([1])))
        try (file as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
        file.removeCachedResourceValue(forKey: .fileProtectionKey)
        let independentlyObserved = try file.resourceValues(forKeys: [.fileProtectionKey]).fileProtection
        XCTAssertFalse(independentlyObserved == .complete, "negative suite requires independently confirmed unavailable complete protection")
        XCTAssertThrowsError(try VaultFiles.protect(directory: directory), "product must refuse unverifiable or weaker complete protection")
        XCTAssertThrowsError(try VaultFiles.verifyProtection(directory: directory), "verification must not infer missing or weaker protection")
        XCTAssertFalse(manager.fileExists(atPath: personal.path), "protection denial must not create a personal vault")
    }
}
