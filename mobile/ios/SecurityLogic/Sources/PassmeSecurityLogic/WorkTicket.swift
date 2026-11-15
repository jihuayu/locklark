import Foundation

public struct WorkCancelled: Error, Sendable { public init() {} }

public final class CancellationScope: @unchecked Sendable {
    private let lock = NSLock()
    private var generation: UInt64 = 0
    public init() {}

    public func ticket() -> WorkTicket {
        lock.lock(); defer { lock.unlock() }
        return WorkTicket(scope: self, generation: generation)
    }

    public func invalidate() {
        lock.lock(); defer { lock.unlock() }
        generation &+= 1
    }

    fileprivate func permits(_ value: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return value == generation
    }
}

public struct WorkTicket: Sendable {
    fileprivate let scope: CancellationScope
    fileprivate let generation: UInt64
    public var isCurrent: Bool { scope.permits(generation) }
    public func check() throws { guard isCurrent else { throw WorkCancelled() } }

    public func run<T>(cleanup: () -> Void = {}, operation: () throws -> T) throws -> T {
        defer { cleanup() }
        try check()
        return try operation()
    }
}
