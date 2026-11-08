import Foundation

/// Bounded, race-free map of opaque connection token -> at most one session.
///
/// A token is in exactly one of two states:
///
/// 1. *opening* - a reservation that has already been charged against the
///    capacity limit. Session creation (for the app: launching the helper) is
///    deliberately done **outside** the lock, so an open can block for as long
///    as the factory needs without holding the store lock and without exposing
///    an unlocked token.
/// 2. *ready* - the created session is bound to the token and can be served.
///
/// Every reservation carries a monotonically increasing generation. When the
/// factory returns, `open` binds the new session only if that exact reservation
/// is still current and the store is still open. Otherwise the created session
/// is closed exactly once and never bound. That makes `close`, `closeAll`, TTL
/// expiry and a concurrent duplicate open unable to strand a late helper.
///
/// The optional profile is part of the reservation identity and of every later
/// lookup: it is compared with *exact* Optional equality, so `nil` only reaches
/// a `nil` binding and a non-nil profile never reaches a different or unbound
/// session. A mismatched `close` never removes or cancels anything.
public final class RelaySessionStore<Session> {
    public typealias Factory = (String?) throws -> Session

    /// Outcome of an open. Only `opened` means a session is bound; every other
    /// case leaves no binding behind.
    public enum OpenResult: Equatable {
        case opened
        /// The token already has a ready session or an in-flight reservation.
        /// Duplicate opens are refused, never used to replace another binding.
        case duplicateToken
        /// Ready sessions plus in-flight reservations already fill the limit.
        case capacityExceeded
        /// The store was torn down (`closeAll`); no open is accepted again.
        case closed
        /// The factory failed; the reservation was released.
        case unavailable
        /// The reservation was cancelled or revoked before the factory
        /// returned; the created session was closed and not bound.
        case revoked
    }

    /// Outcome of a token close.
    public enum CloseResult: Equatable {
        case closedSession
        case cancelledOpening
        case profileMismatch
        case notFound
        case closedStore
    }

    private struct ReadyEntry {
        let createdAt: Date
        let session: Session
    }

    private struct OpeningEntry {
        let generation: UInt64
        let profile: String?
        let createdAt: Date
    }

    private let lock = NSLock()
    private let capacity: Int
    private let openingTTL: TimeInterval
    private let sessionTTL: TimeInterval
    private let now: () -> Date
    private let factory: Factory
    private let closeSession: (Session) -> Void

    private var ready = SessionProfileTable<ReadyEntry>()
    private var opening: [String: OpeningEntry] = [:]
    private var nextGeneration: UInt64 = 1
    private var isClosed = false

    public init(
        capacity: Int = RelayLimits.maxConnections,
        openingTTL: TimeInterval = RelayLimits.openingReservationTTL,
        sessionTTL: TimeInterval = RelayLimits.sessionTTL,
        now: @escaping () -> Date = { Date() },
        make: @escaping Factory,
        close: @escaping (Session) -> Void
    ) {
        self.capacity = max(0, capacity)
        self.openingTTL = max(0, openingTTL)
        self.sessionTTL = max(0, sessionTTL)
        self.now = now
        self.factory = make
        self.closeSession = close
    }

    // MARK: - Open

    /// Reserves one slot, creates the session outside the lock and binds it
    /// only while the reservation is still current.
    @discardableResult
    public func open(token: String, profile: String?) -> OpenResult {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return .closed
        }
        // A duplicate open never replaces another profile or token binding.
        guard opening[token] == nil, !ready.contains(token: token) else {
            lock.unlock()
            return .duplicateToken
        }
        guard ready.count + opening.count < capacity else {
            lock.unlock()
            return .capacityExceeded
        }
        let generation = nextGeneration
        nextGeneration &+= 1
        let createdAt = now()
        opening[token] = OpeningEntry(
            generation: generation,
            profile: profile,
            createdAt: createdAt
        )
        lock.unlock()

        let created: Session
        do {
            created = try factory(profile)
        } catch {
            lock.lock()
            let storeClosed = isClosed
            if let entry = opening[token], entry.generation == generation {
                opening[token] = nil
            }
            lock.unlock()
            return storeClosed ? .closed : .unavailable
        }

        lock.lock()
        let completionDate = now()
        let storeClosed = isClosed
        let current = opening[token]
        let isCurrent = current?.generation == generation
        if isCurrent { opening[token] = nil }
        // The completion is bound to the opening TTL itself, not to whether a
        // sweep happened to run: a factory that returns after the TTL is a
        // late helper and must never be bound.
        let expired = current.map { entry in
            completionDate.timeIntervalSince(entry.createdAt) >= openingTTL
        } ?? true
        guard !storeClosed, isCurrent, !expired else {
            lock.unlock()
            // Late session: never bound, closed exactly once by this opener.
            closeSession(created)
            return storeClosed ? .closed : .revoked
        }
        _ = ready.bind(
            token: token,
            profile: profile,
            session: ReadyEntry(createdAt: createdAt, session: created)
        )
        lock.unlock()
        return .opened
    }

    // MARK: - Lookup / close

    /// Exact-match lookup: the caller's optional profile must equal the stored
    /// one, including the nil == nil case.
    public func session(token: String, profile: String?) -> Session? {
        lock.lock()
        guard !isClosed,
              let entry = ready.session(token: token, profile: profile)
        else {
            lock.unlock()
            return nil
        }
        // Expired ready sessions are refused immediately instead of surviving
        // until the next sweep: evict under the lock, close outside it.
        let expired = now().timeIntervalSince(entry.createdAt) >= sessionTTL
        if expired {
            _ = ready.remove(token: token, profile: profile)
        }
        lock.unlock()
        guard !expired else {
            closeSession(entry.session)
            return nil
        }
        return entry.session
    }

    /// Removes and closes a ready session after an exact profile match.
    @discardableResult
    public func discard(token: String, profile: String?) -> Bool {
        lock.lock()
        let entry = isClosed ? nil : ready.remove(token: token, profile: profile)
        lock.unlock()
        guard let entry else { return false }
        closeSession(entry.session)
        return true
    }

    /// Closes a ready session, or - when the token is still opening - cancels
    /// that reservation so the completing opener refuses to bind. The profile
    /// must match exactly; a mismatched close cancels nothing.
    public func close(token: String, profile: String?) -> CloseResult {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return .closedStore
        }
        if let entry = opening[token] {
            guard SessionProfileTable<ReadyEntry>.matches(
                stored: entry.profile,
                incoming: profile
            ) else {
                lock.unlock()
                return .profileMismatch
            }
            opening[token] = nil
            lock.unlock()
            return .cancelledOpening
        }
        if let entry = ready.remove(token: token, profile: profile) {
            lock.unlock()
            closeSession(entry.session)
            return .closedSession
        }
        let bound = ready.contains(token: token)
        lock.unlock()
        return bound ? .profileMismatch : .notFound
    }

    // MARK: - Teardown and expiry

    /// Revokes every pending reservation and ready session and permanently
    /// closes the store: after this no `open` is accepted, so a worker that was
    /// already accepted before a restart cannot bind a helper to the old store.
    /// Reservations that complete later close their own session exactly once.
    public func closeAll() {
        lock.lock()
        isClosed = true
        let entries = ready.removeAll()
        opening.removeAll()
        lock.unlock()
        for entry in entries {
            closeSession(entry.session)
        }
    }

    /// Closes ready sessions older than the session TTL and releases opening
    /// reservations older than the opening TTL. A released reservation makes
    /// its late completion refuse and close its own session.
    @discardableResult
    public func sweepExpired() -> Int {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return 0
        }
        let date = now()
        let expired = ready.extract { entry in
            date.timeIntervalSince(entry.createdAt) >= sessionTTL
        }
        let staleOpenings = opening
            .filter { date.timeIntervalSince($0.value.createdAt) >= openingTTL }
            .map { $0.key }
        for token in staleOpenings {
            opening[token] = nil
        }
        lock.unlock()
        for entry in expired {
            closeSession(entry.session)
        }
        return expired.count
    }

    // MARK: - Counts

    public var readyCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return ready.count
    }

    public var openingCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return opening.count
    }

    public var totalCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return ready.count + opening.count
    }

    public var closed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isClosed
    }
}
