public struct OperationToken: Equatable, Sendable {
    fileprivate let generation: UInt64
}

public struct OperationBoundary: Sendable {
    private var generation: UInt64 = 0
    private var owner: OperationToken?
    public var isBusy: Bool { owner != nil }

    public init() {}

    public mutating func begin() -> OperationToken {
        generation &+= 1
        let token = OperationToken(generation: generation)
        owner = token
        return token
    }

    @discardableResult
    public mutating func finish(_ token: OperationToken) -> Bool {
        guard owner == token else { return false }
        owner = nil
        return true
    }

    public mutating func cancel() { owner = nil }
}
