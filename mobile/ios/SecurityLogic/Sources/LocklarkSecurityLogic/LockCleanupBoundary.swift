public struct LockCleanupToken: Hashable, Sendable { fileprivate let value: UInt64 }

public struct LockCleanupBoundary: Sendable {
    private var next: UInt64 = 0
    private var pending: Set<LockCleanupToken> = []
    public var isPending: Bool { !pending.isEmpty }
    public init() {}

    public mutating func begin() -> LockCleanupToken {
        next &+= 1
        let token = LockCleanupToken(value: next)
        pending.insert(token)
        return token
    }

    @discardableResult
    public mutating func finish(_ token: LockCleanupToken) -> Bool { pending.remove(token) != nil }
}
