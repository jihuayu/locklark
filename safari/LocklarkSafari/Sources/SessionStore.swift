import Foundation

/// Thread-safe map of opaque connection token -> one helper session. The map
/// is bounded; opening more than the limit refuses rather than pretending to
/// have a native connection.
final class SessionStore {
    private let lock = NSLock()
    private var sessions: [String: HelperSession] = [:]
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
            return send(token: request.token, profileKey: request.profileKey, frame: frame)
        case .poll:
            return poll(token: request.token, profileKey: request.profileKey)
        case .close:
            return close(token: request.token) ?? RelayReply.success(
                token: request.token,
                frames: []
            )
        }
    }

    private func open(token: String, profileKey: String?) -> [String: Any] {
        lock.lock()
        if let existing = sessions[token] {
            existing.close()
            sessions[token] = nil
        }
        guard sessions.count < RelayLimits.maxConnections else {
            lock.unlock()
            return RelayReply.failure(token: token)
        }
        lock.unlock()
        do {
            let session = try HelperSession(identity: identity, profileKey: profileKey)
            lock.lock()
            if sessions[token] != nil || sessions.count >= RelayLimits.maxConnections {
                lock.unlock()
                session.close()
                return RelayReply.failure(token: token)
            }
            sessions[token] = session
            lock.unlock()
            return RelayReply.success(token: token, frames: [])
        } catch {
            return RelayReply.failure(token: token)
        }
    }

    private func matching(
        token: String,
        profileKey: String?
    ) -> HelperSession? {
        lock.lock()
        defer { lock.unlock() }
        guard let session = sessions[token] else { return nil }
        if let stored = session.profile, let incoming = profileKey,
           stored != incoming {
            return nil
        }
        return session
    }

    private func send(
        token: String,
        profileKey: String?,
        frame: [String: Any]
    ) -> [String: Any] {
        guard let session = matching(token: token, profileKey: profileKey) else {
            return RelayReply.failure(token: token)
        }
        do {
            try session.write(frame)
        } catch {
            remove(token: token)
            return RelayReply.failure(token: token)
        }
        return session.replyFrames(token: token)
    }

    private func poll(token: String, profileKey: String?) -> [String: Any] {
        guard let session = matching(token: token, profileKey: profileKey) else {
            return RelayReply.failure(token: token)
        }
        return session.replyFrames(token: token)
    }

    private func close(token: String) -> [String: Any]? {
        lock.lock()
        let session = sessions.removeValue(forKey: token)
        lock.unlock()
        guard let session else { return nil }
        session.close()
        return RelayReply.success(token: token, frames: [])
    }

    func remove(token: String) {
        lock.lock()
        let session = sessions.removeValue(forKey: token)
        lock.unlock()
        session?.close()
    }

    func sweepExpired(now: Date = Date()) {
        lock.lock()
        let expired = sessions.filter {
            now.timeIntervalSince($0.value.createdAt) >= RelayLimits.sessionTTL
        }
        for token in expired.keys {
            sessions[token] = nil
        }
        lock.unlock()
        for session in expired.values {
            session.close()
        }
    }

    func closeAll() {
        lock.lock()
        let all = Array(sessions.values)
        sessions.removeAll()
        lock.unlock()
        for session in all {
            session.close()
        }
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return sessions.count
    }
}
