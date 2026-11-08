import Foundation

/// Bounded token -> exact profile binding shared by the containing app.
///
/// A bearer token alone is not enough to reach a session: the incoming
/// optional profile must equal the stored optional profile exactly. `nil` only
/// matches a session that was opened without a profile (Safari without
/// profiles), and a non-nil profile never matches a `nil` binding or a
/// different profile. Callers serialize access (the app holds a lock).
public struct SessionProfileTable<Session> {
    private struct Entry {
        let profile: String?
        let session: Session
    }

    private var entries: [String: Entry] = [:]

    public init() {}

    public var count: Int { entries.count }

    /// Exact Optional equality: a mismatched profile never resolves a session.
    public static func matches(stored: String?, incoming: String?) -> Bool {
        stored == incoming
    }

    public func session(token: String, profile: String?) -> Session? {
        guard let entry = entries[token],
              SessionProfileTable.matches(
                stored: entry.profile,
                incoming: profile
              )
        else { return nil }
        return entry.session
    }

    /// Stores the binding and returns a displaced session for the same token,
    /// if any, so the caller can close it.
    public mutating func bind(
        token: String,
        profile: String?,
        session: Session
    ) -> Session? {
        let displaced = entries[token]?.session
        entries[token] = Entry(profile: profile, session: session)
        return displaced
    }

    /// Removes a binding only after the exact profile check passed, so a
    /// mismatched close can never tear down someone else's session. The
    /// session is still in the table if the check fails.
    public mutating func remove(token: String, profile: String?) -> Session? {
        guard let entry = entries[token],
              SessionProfileTable.matches(
                stored: entry.profile,
                incoming: profile
              )
        else { return nil }
        entries[token] = nil
        return entry.session
    }

    /// Unconditional removal. Only open (to replace a binding), TTL expiry and
    /// teardown may use this; send/poll/close must use the exact-match call.
    public mutating func removeValue(token: String) -> Session? {
        entries.removeValue(forKey: token)?.session
    }

    public mutating func extract(where predicate: (Session) -> Bool) -> [Session] {
        let tokens = entries
            .filter { predicate($0.value.session) }
            .map { $0.key }
        var removed: [Session] = []
        for token in tokens {
            if let entry = entries.removeValue(forKey: token) {
                removed.append(entry.session)
            }
        }
        return removed
    }

    public mutating func removeAll() -> [Session] {
        let all = entries.values.map { $0.session }
        entries.removeAll()
        return all
    }
}
