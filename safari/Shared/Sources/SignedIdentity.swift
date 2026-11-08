import Foundation

public enum IdentityError: Error, Equatable {
    case missing(String)
    case blank(String)
    case placeholder(String)
    case malformedTeamID
    case malformedBundleID
    case malformedAppGroup
    case bundleMismatch
    case notFixedIdentity
}

public enum InfoKeys {
    public static let teamID = "LocklarkTeamID"
    public static let appGroupID = "LocklarkAppGroupID"
    public static let extensionBundleID = "LocklarkExtensionBundleID"
    public static let containingAppBundleID = "LocklarkAppBundleID"
}

/// Identity values are read from the signed Info.plist of whichever target is
/// asking. Placeholders, blanks and unresolved build settings fail closed.
public struct ConfiguredIdentity: Equatable {
    public static let fixedContainingAppBundleID = "org.locklark.browser.safari"
    public static let fixedExtensionBundleID = "org.locklark.browser.safari.Extension"
    public static let fixedAppGroupID = "group.org.locklark.browser.safari"

    public let teamID: String
    public let appGroupID: String
    public let extensionBundleID: String
    public let containingAppBundleID: String

    public init(
        teamID: String,
        appGroupID: String,
        extensionBundleID: String,
        containingAppBundleID: String
    ) {
        self.teamID = teamID
        self.appGroupID = appGroupID
        self.extensionBundleID = extensionBundleID
        self.containingAppBundleID = containingAppBundleID
    }

    public static func from(infoDictionary: [String: Any]) throws -> ConfiguredIdentity {
        func required(_ key: String) throws -> String {
            guard let raw = infoDictionary[key] as? String else {
                throw IdentityError.missing(key)
            }
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { throw IdentityError.blank(key) }
            guard !isPlaceholder(trimmed) else {
                throw IdentityError.placeholder(key)
            }
            return trimmed
        }
        let identity = ConfiguredIdentity(
            teamID: try required(InfoKeys.teamID),
            appGroupID: try required(InfoKeys.appGroupID),
            extensionBundleID: try required(InfoKeys.extensionBundleID),
            containingAppBundleID: try required(InfoKeys.containingAppBundleID)
        )
        try identity.validate()
        return identity
    }

    public static func from(bundle: Bundle) throws -> ConfiguredIdentity {
        try from(infoDictionary: bundle.infoDictionary ?? [:])
    }

    public static func isPlaceholder(_ value: String) -> Bool {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return true }
        if text.hasPrefix("$(") || text.contains("$(") { return true }
        let upper = text.uppercased()
        for marker in [
            "REPLACE",
            "CHANGEME",
            "CHANGE_ME",
            "YOUR_",
            "PLACEHOLDER",
            "EXAMPLE",
            "TEAMID",
            "TEAM_ID",
            "TODO",
            "XXXX",
            "UNSIGNED",
        ] where upper.contains(marker) {
            return true
        }
        return false
    }

    public static func isValidTeamID(_ value: String) -> Bool {
        guard value.utf8.count == 10 else { return false }
        for byte in value.utf8 {
            switch byte {
            case 48...57, 65...90: continue
            default: return false
            }
        }
        return true
    }

    public static func isValidBundleID(_ value: String) -> Bool {
        guard value.utf8.count >= 3 && value.utf8.count <= 200 else { return false }
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count >= 2 else { return false }
        for component in components {
            guard !component.isEmpty, component.utf8.count <= 63 else { return false }
            for byte in component.utf8 {
                switch byte {
                case 48...57, 65...90, 97...122, 45: continue
                default: return false
                }
            }
        }
        return true
    }

    public static func isValidAppGroupID(_ value: String) -> Bool {
        guard value.hasPrefix("group.") else { return false }
        let suffix = String(value.dropFirst("group.".count))
        return isValidBundleID(suffix) && suffix.split(separator: ".").count >= 2
    }

    public func validate() throws {
        guard !ConfiguredIdentity.isPlaceholder(teamID),
              ConfiguredIdentity.isValidTeamID(teamID)
        else { throw IdentityError.malformedTeamID }
        guard !ConfiguredIdentity.isPlaceholder(appGroupID),
              ConfiguredIdentity.isValidAppGroupID(appGroupID)
        else { throw IdentityError.malformedAppGroup }
        guard !ConfiguredIdentity.isPlaceholder(containingAppBundleID),
              ConfiguredIdentity.isValidBundleID(containingAppBundleID)
        else { throw IdentityError.malformedBundleID }
        guard !ConfiguredIdentity.isPlaceholder(extensionBundleID),
              ConfiguredIdentity.isValidBundleID(extensionBundleID)
        else { throw IdentityError.malformedBundleID }
        guard extensionBundleID == containingAppBundleID + ".Extension" else {
            throw IdentityError.bundleMismatch
        }
        guard containingAppBundleID == ConfiguredIdentity.fixedContainingAppBundleID,
              extensionBundleID == ConfiguredIdentity.fixedExtensionBundleID,
              appGroupID == ConfiguredIdentity.fixedAppGroupID
        else { throw IdentityError.notFixedIdentity }
    }

    public func validateRuntimeBundles(
        actualExtensionBundleID: String?,
        actualContainingAppBundleID: String?
    ) throws {
        guard actualExtensionBundleID == extensionBundleID else {
            throw IdentityError.bundleMismatch
        }
        guard actualContainingAppBundleID == containingAppBundleID else {
            throw IdentityError.bundleMismatch
        }
    }
}
