import Foundation

public enum ProtectionAttribute {
    // FileManager may return the raw NSString/String rather than its Swift
    // tagged-string wrapper. Accept only the exact complete-protection value.
    public static func isComplete(_ value: Any?) -> Bool {
        if let typed = value as? FileProtectionType {
            return typed.rawValue == FileProtectionType.complete.rawValue
        }
        guard let raw = value as? String else { return false }
        return raw == FileProtectionType.complete.rawValue
    }
}
