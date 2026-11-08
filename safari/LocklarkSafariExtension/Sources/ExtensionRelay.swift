import Foundation

/// Extension-side relay. It validates the Safari message envelope, loads the
/// signed identity from Info.plist, and forwards only the fixed operation
/// envelope over the app-group socket. It never launches processes, never
/// fabricates a native reply and never logs request or error contents.
///
/// The profile is never taken from the JS message: `RelayRequest.parse` refuses
/// any profile field from JS, and the only profile that is forwarded is the one
/// the native handler context supplied (SFExtensionProfileKey). It is forwarded
/// on every operation, so send/poll/close stay bound to the same profile.
final class ExtensionRelay {
    private let lock = NSLock()
    private var connection: AppGroupSocketClient?
    private var configuration: ExtensionConfiguration?

    func handle(rawMessage: Any?, profileKey: String?) -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard let request = RelayRequest.parse(rawMessage) else {
            return RelayReply.protocolFailure()
        }
        // Trusted native context only: an invalid, oversized or NUL-bearing
        // profile fails closed instead of being dropped or reinterpreted.
        if let profileKey, !RelayEnvelope.isValidProfileKey(profileKey) {
            resetConnection()
            return RelayReply.failure(token: request.token)
        }
        do {
            let configuration = try currentConfiguration()
            let connection = try currentConnection(configuration)
            let rawReply = try connection.request(
                request.forwardingEnvelope(profileKey: profileKey)
            )
            guard let reply = RelayReply.parse(
                rawReply,
                expectedToken: request.token
            ) else {
                resetConnection()
                return RelayReply.failure(token: request.token)
            }
            return reply
        } catch {
            resetConnection()
            return RelayReply.failure(token: request.token)
        }
    }

    private func currentConfiguration() throws -> ExtensionConfiguration {
        if let configuration { return configuration }
        let loaded = try ExtensionConfiguration.load()
        configuration = loaded
        return loaded
    }

    private func currentConnection(
        _ configuration: ExtensionConfiguration
    ) throws -> AppGroupSocketClient {
        if let connection { return connection }
        let opened = try AppGroupSocketClient(socketURL: configuration.socketURL)
        connection = opened
        return opened
    }

    private func resetConnection() {
        connection?.close()
        connection = nil
    }
}
