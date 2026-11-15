import Foundation

struct ExtensionConfiguration {
    let identity: ConfiguredIdentity
    let socketURL: URL

    static func load(bundle: Bundle = .main) throws -> ExtensionConfiguration {
        let identity = try ConfiguredIdentity.from(bundle: bundle)
        try identity.validateRuntimeBundles(
            actualExtensionBundleID: bundle.bundleIdentifier,
            actualContainingAppBundleID: identity.containingAppBundleID
        )
        let container = try PathPolicy.appGroupContainer(
            appGroupID: identity.appGroupID
        )
        let socketURL = PathPolicy.relaySocketURL(container: container)
        try PathPolicy.validateRelaySocket(socketURL, container: container)
        guard FileManager.default.fileExists(atPath: socketURL.path) else {
            throw RelayError.unavailable
        }
        return ExtensionConfiguration(identity: identity, socketURL: socketURL)
    }
}
