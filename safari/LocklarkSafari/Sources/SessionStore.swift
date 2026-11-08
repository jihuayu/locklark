import Foundation

/// Thread-safe map of opaque connection token -> one helper session. The map
/// is bounded; opening more than the limit refuses rather than pretending to
/// have a native connection.
///
/// Every operation after open (send/poll/close) must carry the *same* optional
/// profile the session was opened with. The comparison is exact Optional
/// equality, so `nil` only reaches a `nil`-bound session (Safari without
/// profiles) and can never reach a profiled one, or vice versa. A mismatched
/// close is refused without removing the session.
final class SessionStore {
    private let lock = NSLock()
    private var table = SessionProfileTable<HelperSession>()
    private let identity: ConfiguredIdentity

    init(identity: ConfiguredIdentity) {
        self.identity = identity
    }

    func handle(_ request: RelayRequest) -> [String: Any] {
        switch request.operation {
        case .open:
            return open(token: request.token, profileKey: request.profileKey)
        case .send:
            guard let frame = request.frame else {
                return RelayReply.failure(token: request.token)
            }
            return send(
                token: request.token,
                profileKey: request.profileKey,
                frame: frame
            )
        case .poll:
            return poll(token: request.token, profileKey: request.profileKey)
        case .close:
            return close(token: request.token, profileKey: request.profileKey)
        }
    }

    private func open(token: String, profileKey: String?) -> [String: Any] {
        lock.lock()
        let displaced = table.removeValue(token: token)
        let full = table.count >= RelayLimits.maxConnections
        lock.unlock()
        displaced?.close()
        guard !full else { return RelayReply.failure(token: token) }
        do {
            let session = try HelperSession(identity: identity, profileKey: profileKey)
            lock.lock()
            let existing = table.removeValue(token: token)
            let overflow = table.count >= RelayLimits.maxConnections
            if !overflow {
                _ = table.bind(
                    token: token,
                    profile: profileKey,
                    session: session
                )
            }
            lock.unlock()
            existing?.close()
            guard !overflow else {
                session.close()
                return RelayReply.failure(token: token)
            }
            return RelayReply.success(token: token, frames: [])
        } catch {
            return RelayReply.failure(token: token)
        }
    }

    /// Exact-match lookup: the caller's optional profile must equal the stored
    /// one, including the nil == nil case.
    private func exactSession(
        token: String,
        profileKey: String?
    ) -> HelperSession? {
        lock.lock()
        defer { lock.unlock() }
        return table.session(token: token, profile: profileKey)
    }

    private func send(
        token: String,
        profileKey: String?,
        frame: [String: Any]
    ) -> [String: Any] {
        guard let session = exactSession(token: token, profileKey: profileKey) else {
            return RelayReply.failure(token: token)
        }
        do {
            // A frame is written once. After a partial write the session is
            // dropped instead of being retried.
            try session.write(frame)
        } catch {
            remove(token: token, profileKey: profileKey)
            return RelayReply.failure(token: token)
        }
        return session.replyFrames(token: token)
    }

    private func poll(token: String, profileKey: String?) -> [String: Any] {
        guard let session = exactSession(token: token, profileKey: profileKey) else {
            return RelayReply.failure(token: token)
        }
        return session.replyFrames(token: token)
    }

    /// The profile check happens before any removal: a mismatched profile gets
    /// a failure reply and the session (and its helper) stays intact.
    private func close(token: String, profileKey: String?) -> [String: Any] {
        lock.lock()
        let session = table.remove(token: token, profile: profileKey)
        lock.unlock()
        guard let session else { return RelayReply.failure(token: token) }
        session.close()
        return RelayReply.success(token: token, frames: [])
    }

    private func remove(token: String, profileKey: String?) {
        lock.lock()
        let session = table.remove(token: token, profile: profileKey)
        lock.unlock()
        session?.close()
    }

    func sweepExpired(now: Date = Date()) {
        lock.lock()
        let expired = table.extract { session in
            now.timeIntervalSince(session.createdAt) >= RelayLimits.sessionTTL
        }
        lock.unlock()
        for session in expired {
            session.close()
        }
    }

    func closeAll() {
        lock.lock()
        let all = table.removeAll()
        lock.unlock()
        for session in all {
            session.close()
        }
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return table.count
    }
}
