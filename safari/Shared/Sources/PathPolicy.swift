import Foundation

/// Path derivation is fixed: the only accepted root is the app-group container
/// returned by FileManager, and the only accepted socket is native/relay.sock
/// beneath it. There is deliberately no API that accepts a path, executable or
/// argv supplied by JavaScript.
public enum PathPolicy {
    public static func relaySocketURL(container: URL) -> URL {
        container
            .appendingPathComponent(RelayLimits.relayDirectoryName, isDirectory: true)
            .appendingPathComponent(RelayLimits.relaySocketName, isDirectory: false)
    }

    public static func isContained(_ candidate: URL, in root: URL) -> Bool {
        let rootPath = root.standardizedFileURL.resolvingSymlinksInPath().path
        let candidatePath = candidate.standardizedFileURL.resolvingSymlinksInPath().path
        guard !rootPath.isEmpty, candidatePath != rootPath else { return false }
        return candidatePath.hasPrefix(rootPath + "/")
    }

    public static func validateRelaySocket(_ socketURL: URL, container: URL) throws {
        let expected = relaySocketURL(container: container)
        let components = socketURL.path.split(separator: "/")
        guard !components.contains(where: { $0 == ".." }),
              socketURL.path == expected.path,
              socketURL.standardizedFileURL == expected.standardizedFileURL
        else { throw RelayError.invalidConfiguration }
        guard isContained(socketURL, in: container) else {
            throw RelayError.invalidConfiguration
        }
    }

    public static func appGroupContainer(
        appGroupID: String,
        fileManager: FileManager = .default
    ) throws -> URL {
        guard !ConfiguredIdentity.isPlaceholder(appGroupID),
              ConfiguredIdentity.isValidAppGroupID(appGroupID)
        else { throw IdentityError.malformedAppGroup }
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else { throw RelayError.unavailable }
        return container
    }
}
