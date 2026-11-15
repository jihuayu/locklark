public struct ExposureToken: Equatable, Sendable {
    fileprivate let operation: OperationToken
}

public struct ExposureBoundary: Sendable {
    private var operation = OperationBoundary()
    private var current: ExposureToken?
    public init() {}

    public mutating func begin() -> ExposureToken {
        let token = ExposureToken(operation: operation.begin())
        current = token
        return token
    }

    public func owns(_ token: ExposureToken) -> Bool { current == token }
    public mutating func cancel() { current = nil; operation.cancel() }
    public mutating func expire(_ token: ExposureToken) -> Bool {
        guard current == token, operation.finish(token.operation) else { return false }
        current = nil
        return true
    }
}
