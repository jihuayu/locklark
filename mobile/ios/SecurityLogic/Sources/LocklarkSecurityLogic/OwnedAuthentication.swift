public struct AuthenticationToken: Equatable, Sendable {
    fileprivate let generation: UInt64
}

// Only a locked app's explicitly owned OS prompt may survive inactivity.
// This state never authorizes a vault call until active, and holds no secret.
public struct OwnedAuthentication: Sendable {
    private var generation: UInt64 = 0
    private var current: AuthenticationToken?
    private var started: Int64 = 0
    private var authorized: Int64?
    public init() {}

    public mutating func begin(vaultLocked: Bool, isActive: Bool, monotonicNow: Int64) -> AuthenticationToken? {
        guard vaultLocked, isActive else { return nil }
        generation &+= 1
        let token = AuthenticationToken(generation: generation)
        current = token
        started = monotonicNow
        authorized = nil
        return token
    }

    public func owns(_ token: AuthenticationToken) -> Bool { current == token }
    public mutating func cancel() { current = nil; authorized = nil }

    public mutating func systemSucceeded(_ token: AuthenticationToken, monotonicNow: Int64) -> Bool {
        guard owns(token), authorized == nil, Self.within(monotonicNow, since: started, limit: 60_000) else { return false }
        authorized = monotonicNow
        return true
    }

    public func ready(_ token: AuthenticationToken, isActive: Bool, monotonicNow: Int64) -> Bool {
        guard isActive, owns(token), let authorized else { return false }
        return Self.within(monotonicNow, since: authorized, limit: 10_000)
    }

    public mutating func consume(_ token: AuthenticationToken, isActive: Bool, monotonicNow: Int64) -> Bool {
        guard ready(token, isActive: isActive, monotonicNow: monotonicNow) else { return false }
        cancel()
        return true
    }

    private static func within(_ now: Int64, since: Int64, limit: Int64) -> Bool {
        let (elapsed, overflow) = now.subtractingReportingOverflow(since)
        return !overflow && elapsed >= 0 && elapsed < limit
    }
}
