import Foundation

/// App-side adapter from the relay protocol to the bounded session store.
///
/// The store itself (`RelaySessionStore`) owns every state transition: reserve
/// capacity before launching the helper, bind only if the reservation is still
/// current, revoke everything on `closeAll`, and permanently refuse new opens
/// once it has been closed. A `SessionStore` is therefore bound to one
/// `RelayServer` generation: after a restart the server installs a new store and
/// the old one has already been closed, so a connection accepted before the
/// restart can never launch a helper through it.
final class SessionStore {
    private let store: RelaySessionStore<HelperSession>

    init(identity: ConfiguredIdentity) {
        store = RelaySessionStore<HelperSession>(
            capacity: RelayLimits.maxConnections,
            openingTTL: RelayLimits.openingReservationTTL,
            sessionTTL: RelayLimits.sessionTTL,
            make: { profileKey in
                try HelperSession(identity: identity, profileKey: profileKey)
            },
            close: { session in session.close() }
        )
    }

    func handle(_ request: RelayRequest) -> [String: Any] {
        switch request.operation {
        case .open:
            let result = store.open(
                token: request.token,
                profile: request.profileKey
            )
            if result == .opened {
                return RelayReply.success(token: request.token, frames: [])
            }
            return RelayReply.failure(token: request.token)
        case .send:
            guard let frame = request.frame,
                  let session = store.session(
                    token: request.token,
                    profile: request.profileKey
                  )
            else { return RelayReply.failure(token: request.token) }
            // A helper that already died is unusable: release its binding (so
            // the slot is reusable now, not after the session TTL) instead of
            // replying from a dead session.
            guard session.isUsable else {
                discard(session, for: request)
                return RelayReply.failure(token: request.token)
            }
            do {
                // A frame is written once. After a partial write the session
                // is dropped instead of being retried.
                try session.write(frame)
            } catch {
                discard(session, for: request)
                return RelayReply.failure(token: request.token)
            }
            return reply(from: session, for: request)
        case .poll:
            guard let session = store.session(
                token: request.token,
                profile: request.profileKey
            ) else { return RelayReply.failure(token: request.token) }
            return reply(from: session, for: request)
        case .close:
            switch store.close(
                token: request.token,
                profile: request.profileKey
            ) {
            case .closedSession, .cancelledOpening:
                return RelayReply.success(token: request.token, frames: [])
            case .profileMismatch, .notFound, .closedStore:
                return RelayReply.failure(token: request.token)
            }
        }
    }

    /// Replies from an already captured session, dropping its binding as soon
    /// as the helper is unusable. A dead helper (stdout EOF, terminated
    /// process, failed write or protocol error) must not keep consuming one of
    /// the bounded helper slots until the session TTL expires: a poll that
    /// cannot be served releases the exact binding it captured and answers
    /// with the fixed failure reply.
    private func reply(
        from session: HelperSession,
        for request: RelayRequest
    ) -> [String: Any] {
        guard session.isUsable else {
            discard(session, for: request)
            return RelayReply.failure(token: request.token)
        }
        let frames = session.replyFrames(token: request.token)
        // The helper can die while the reply is assembled: check again and
        // never treat a dead binding as servable.
        guard session.isUsable else {
            discard(session, for: request)
            return RelayReply.failure(token: request.token)
        }
        return frames
    }

    /// Drops exactly the binding this request captured. The store compares
    /// session identity under its own lock, so a failure from an old helper can
    /// never revoke a replacement bound to the same token/profile by a
    /// concurrent close + reopen. Closing happens in the store, outside its
    /// lock, exactly as for every other removal.
    private func discard(_ session: HelperSession, for request: RelayRequest) {
        store.discard(
            token: request.token,
            profile: request.profileKey,
            matching: { $0 === session }
        )
    }

    /// TTL cleanup: ready sessions past the session TTL close, opening
    /// reservations past the (much shorter) opening TTL are released so a late
    /// helper launch is refused and closed by its own opener.
    func sweepExpired() {
        store.sweepExpired()
    }

    func closeAll() {
        store.closeAll()
    }

    var count: Int {
        store.readyCount
    }
}
