public struct VaultTarget: Equatable, Sendable {
    public let id: String
    public let revision: String
    public let field: String

    public init(id: String, revision: String, field: String) {
        self.id = id
        self.revision = revision
        self.field = field
    }
}

public struct ScreenToken: Equatable, Sendable {
    fileprivate let generation: UInt64
    fileprivate let target: VaultTarget?
}

public struct SessionBoundary: Sendable {
    public enum Phase: Equatable, Sendable { case locked, unlocking, unlocked }
    public private(set) var phase: Phase = .locked
    public private(set) var isActive = true
    public private(set) var target: VaultTarget?
    private var generation: UInt64 = 0

    public init() {}

    public mutating func beginUnlock() -> ScreenToken? {
        guard isActive else { return nil }
        generation &+= 1
        phase = .unlocking
        target = nil
        return ScreenToken(generation: generation, target: nil)
    }

    @discardableResult
    public mutating func finishUnlock(_ token: ScreenToken) -> Bool {
        guard isActive, phase == .unlocking, token.generation == generation else { return false }
        phase = .unlocked
        return true
    }

    public mutating func select(_ newTarget: VaultTarget?) {
        generation &+= 1
        target = newTarget
    }

    public func capture() -> ScreenToken? {
        guard isActive, phase == .unlocked else { return nil }
        return ScreenToken(generation: generation, target: target)
    }

    public func permits(_ token: ScreenToken) -> Bool {
        isActive && phase == .unlocked && token.generation == generation && token.target == target
    }

    public mutating func lock() {
        generation &+= 1
        phase = .locked
        target = nil
    }

    public mutating func resignActive() {
        isActive = false
        lock()
    }

    public mutating func becomeActive() {
        isActive = true
    }
}
