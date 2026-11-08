import Foundation

/// Decodes Safari's native `SFExtensionProfileKey` value into the canonical
/// profile identity forwarded on the app-group hop.
///
/// Apple's messaging example passes the profile as a `UUID`, so a present
/// value is only accepted as a `UUID` and becomes its lowercase canonical
/// string. A present value of any other type is a fault, never `nil`: a `nil`
/// fallback would collapse profile identity and let a profiled session bind
/// like Safari without profiles.
public enum TrustedSafariProfile {
    public static func identifier(_ value: Any?) throws -> String? {
        guard let value else { return nil }
        guard let profile = value as? UUID else {
            throw RelayError.unavailable
        }
        return profile.uuidString.lowercased()
    }
}
