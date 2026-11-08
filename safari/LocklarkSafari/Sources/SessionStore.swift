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
            do {
                // A frame is written once. After a partial write the session
                // is dropped instead of being retried.
                try session.write(frame)
            } catch {
                store.discard(
                    token: request.token,
                    profile: request.profileKey
                )
                return RelayReply.failure(token: request.token)
            }
            return session.replyFrames(token: request.token)
        case .poll:
            guard let session = store.session(
                token: request.token,
                profile: request.profileKey
            ) else { return RelayReply.failure(token: request.token) }
            return session.replyFrames(token: request.token)
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
