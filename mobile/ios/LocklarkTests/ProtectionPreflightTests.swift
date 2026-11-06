import Foundation
import XCTest
import LocklarkSecurityLogic
@testable import Locklark

// Public, non-secret fixture. Never serialize paths, attribute contents or
// NSError descriptions; only this fixed schema is published by the CI reader.
final class ProtectionPreflightTests: XCTestCase {
    private func failure(_ error: Error) -> [String: Any] {
        let error = error as NSError
        let domains = [NSCocoaErrorDomain, NSPOSIXErrorDomain, NSOSStatusErrorDomain, NSMachErrorDomain]
        let codes = [-50, -4, 0, 1, 2, 4, 5, 13, 22, 45, 95, 257, 260, 262, 512, 513, 516, 640, 642, 3328, 4097, 4099]
        return ["status": "error", "domain": domains.contains(error.domain) ? error.domain : "other", "code": codes.contains(error.code) ? error.code as Any : "other"]
    }

    private func attempt(_ action: () throws -> Void) -> [String: Any] {
        do { try action(); return ["status": "ok"] } catch { return failure(error) }
    }

    private func protection(_ url: URL) -> [String: Any] {
        do {
            let value = try FileManager.default.attributesOfItem(atPath: url.path)[.protectionKey]
            let representation = value == nil ? "missing" : (value is FileProtectionType ? "typed" : (value is String ? "string" : "other"))
            let raw = (value as? FileProtectionType)?.rawValue ?? (value as? String)
            let weaker = [FileProtectionType.none.rawValue, FileProtectionType.completeUnlessOpen.rawValue, FileProtectionType.completeUntilFirstUserAuthentication.rawValue]
            let classification = ProtectionAttribute.isComplete(value) ? "complete" : (raw.map { weaker.contains($0) } == true ? "weaker" : "unknown")
            return ["status": "ok", "representation": representation, "class": classification]
        } catch { return failure(error) }
    }

    private func backup(_ url: URL, fresh: Bool) -> [String: Any] {
        var url = url
        if fresh { url.removeCachedResourceValue(forKey: .isExcludedFromBackupKey) }
        do {
            let flag = try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
            return ["status": "ok", "value": flag.map { $0 ? "true" : "false" } ?? "nil"]
        } catch { return failure(error) }
    }

    private func urlProtection(_ original: URL) -> [String: Any] {
        var fresh = original
        fresh.removeCachedResourceValue(forKey: .fileProtectionKey)
        do {
            let value = try fresh.resourceValues(forKeys: [.fileProtectionKey]).fileProtection
            let weaker: [URLFileProtection] = [.none, .completeUnlessOpen, .completeUntilFirstUserAuthentication]
            let classification = value == .complete ? "complete" : (value.map { weaker.contains($0) } == true ? "weaker" : "unknown")
            return ["status": "ok", "representation": value == nil ? "missing" : "typed", "class": classification]
        } catch { return failure(error) }
    }

    private func node(_ original: URL, role: String, rawSetter: Bool) -> [String: Any] {
        var url = original
        var output: [String: Any] = ["role": role, "setter": rawSetter ? "raw" : "typed", "complete_before": protection(url)]
        do {
            let symbolic = try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink
            output["symlink"] = ["status": "ok", "value": symbolic.map { $0 ? "true" : "false" } ?? "nil"]
        } catch { output["symlink"] = failure(error) }
        output["backup_write"] = attempt {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try url.setResourceValues(values)
        }
        output["backup_cached"] = backup(url, fresh: false)
        output["backup_fresh"] = backup(url, fresh: true)
        output["complete_write"] = attempt {
            let value: Any = rawSetter ? FileProtectionType.complete.rawValue as Any : FileProtectionType.complete as Any
            try FileManager.default.setAttributes([.protectionKey: value], ofItemAtPath: url.path)
        }
        output["complete_after"] = protection(url)
        output["url_before"] = urlProtection(url)
        output["url_write"] = attempt { try (url as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey) }
        output["url_after"] = urlProtection(url)
        output["legacy_after_url"] = protection(url)
        return output
    }

    func testNativeProtectionPreflight() {
        var report: [String: Any] = ["version": 1, "wrapper": "not-run", "nodes": []]
        defer {
            if let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), let text = String(data: data, encoding: .utf8) {
                print("LOCKLARK_PROTECTION_PROBE " + text)
            }
        }
        do {
            let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            let directory = support.appendingPathComponent("Protection-Probe-" + UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete.rawValue])
            defer { try? FileManager.default.removeItem(at: directory) }
            let primary = directory.appendingPathComponent("primary", isDirectory: true)
            try FileManager.default.createDirectory(at: primary, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete.rawValue])
            XCTAssertTrue(FileManager.default.createFile(atPath: primary.appendingPathComponent("public-fixture").path, contents: Data([1])))
            do { try VaultFiles.protect(directory: primary); report["wrapper"] = "pass" }
            catch { report["wrapper"] = "fail"; report["wrapper_error"] = failure(error) }
            var nodes: [[String: Any]] = []
            for raw in [false, true] {
                let root = directory.appendingPathComponent(raw ? "raw" : "typed", isDirectory: true)
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.protectionKey: FileProtectionType.complete.rawValue])
                let file = root.appendingPathComponent("public-fixture")
                XCTAssertTrue(FileManager.default.createFile(atPath: file.path, contents: Data([1])))
                nodes.append(node(root, role: "directory", rawSetter: raw))
                nodes.append(node(file, role: "file", rawSetter: raw))
            }
            report["nodes"] = nodes
            report["enumeration"] = attempt {
                let entries = try FileManager.default.contentsOfDirectory(at: primary, includingPropertiesForKeys: [.isSymbolicLinkKey])
                guard entries.count == 1 else { throw PlatformProtectionError.storageDenied }
            }
            report["setup"] = ["status": "ok"]
#if targetEnvironment(simulator)
            if report["wrapper"] as? String != "pass" {
                print("LOCKLARK_SIMULATOR_PREFLIGHT simulator capability-refusal verified")
            }
#endif
            XCTAssertTrue(report["wrapper"] as? String == "pass", "native file protection preflight failed")
        } catch {
            report["setup"] = failure(error)
            XCTFail("native protection preflight setup failed")
        }
    }
}
