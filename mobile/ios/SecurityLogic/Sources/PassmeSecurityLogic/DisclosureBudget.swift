public struct DisclosureBudget: Sendable {
    private let from: Int64
    private let until: Int64
    private let issuedWall: Int64
    private let cap: Int64

    public init?(from: Int64, until: Int64, issuedWall: Int64) {
        guard from <= issuedWall, issuedWall < until else { return nil }
        let (remaining, overflow) = until.subtractingReportingOverflow(issuedWall)
        guard !overflow, remaining > 0 else { return nil }
        self.from = from
        self.until = until
        self.issuedWall = issuedWall
        self.cap = min(15_000, remaining)
    }

    public func permits(wallNow: Int64, elapsedMilliseconds: Int64) -> Bool {
        elapsedMilliseconds >= 0 && elapsedMilliseconds < cap &&
            wallNow >= issuedWall && wallNow >= from && wallNow < until
    }
}
