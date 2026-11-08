import Foundation

/// Serializes every operation on one write-only pipe descriptor.
///
/// The descriptor, the bounded write and the resource teardown all run on the
/// same private serial queue, so two writes can never overlap and the
/// descriptor can never be closed underneath an in-flight write. `revoke`
/// records the decision synchronously under a short state lock: a queued write
/// re-checks it inside its own queued operation before it touches the
/// descriptor, and an in-flight bounded write observes it through the
/// cancellation callback, so `close` only waits a bounded time. Teardown runs
/// exactly once and always on that serial queue.
public final class SerializedPipeWriter {
    public typealias WriteOperation = (
        _ fd: Int32, _ data: Data, _ deadline: DispatchTime,
        _ isCancelled: () -> Bool
    ) throws -> Void

    /// Absolute monotonic bound for one queued write; also the close wait.
    public static let defaultDeadline: TimeInterval = 2

    /// Identity token for this instance's own queue. A close that runs on one
    /// gate's queue must never be mistaken for this gate's queue.
    private final class QueueToken {}
    private static let queueKey = DispatchSpecificKey<QueueToken>()
    private let token = QueueToken()
    private let stateLock = NSLock()
    private let queue = DispatchQueue(label: "org.locklark.safari.pipe.writer")
    private let fd: Int32
    private let deadline: TimeInterval
    private let writeOperation: WriteOperation
    private let teardownOperation: () -> Void
    private var revoked = false
    private var inFlight: DispatchSemaphore?
    private var teardownScheduled = false
    private var tornDown = false

    public init(
        fd: Int32,
        deadline: TimeInterval = SerializedPipeWriter.defaultDeadline,
        write: @escaping WriteOperation,
        teardown: @escaping () -> Void
    ) {
        self.fd = fd
        self.deadline = max(0, deadline)
        self.writeOperation = write
        self.teardownOperation = teardown
        queue.setSpecific(key: Self.queueKey, value: token)
    }

    /// Synchronously refuses every later write, including one already queued.
    public func revoke() {
        stateLock.lock()
        revoked = true
        stateLock.unlock()
    }

    /// Writes one frame on the serial queue, or throws the fixed `unavailable`.
    public func write(_ data: Data) throws {
        try queue.sync {
            guard let completion = beginOperation() else {
                throw RelayError.unavailable
            }
            defer { endOperation(completion) }
            try writeOperation(fd, data, DispatchTime.now() + deadline) {
                self.stateLock.lock()
                defer { self.stateLock.unlock() }
                return self.revoked
            }
        }
    }

    /// Revokes, waits at most `wait` for the current write, then tears the
    /// descriptor down exactly once. No state lock is held while waiting.
    public func close(wait: TimeInterval = SerializedPipeWriter.defaultDeadline) {
        revoke()
        guard !isOnOwnQueue else {
            // Re-entrant close from this gate's own write operation: waiting on
            // our own completion would stall, and an inline teardown would
            // close the descriptor while that operation is still running. The
            // async block runs after it instead.
            scheduleTeardown(afterCurrentOperation: true)
            return
        }
        stateLock.lock()
        let completion = inFlight
        stateLock.unlock()
        let outcome = completion?.wait(timeout: .now() + max(0, wait))
        scheduleTeardown(afterCurrentOperation: (outcome ?? .success) == .timedOut)
    }

    private var isOnOwnQueue: Bool {
        DispatchQueue.getSpecific(key: Self.queueKey) === token
    }

    private func beginOperation() -> DispatchSemaphore? {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !revoked else { return nil }
        let completion = DispatchSemaphore(value: 0)
        inFlight = completion
        return completion
    }

    private func endOperation(_ completion: DispatchSemaphore) {
        stateLock.lock()
        if inFlight === completion { inFlight = nil }
        stateLock.unlock()
        completion.signal()
    }

    /// Exactly one teardown, always on this gate's serial queue and never
    /// before the operation that is currently running has finished.
    private func scheduleTeardown(afterCurrentOperation: Bool) {
        stateLock.lock()
        if teardownScheduled {
            stateLock.unlock()
            return
        }
        teardownScheduled = true
        stateLock.unlock()
        if afterCurrentOperation {
            queue.async { self.runTeardown() }
        } else {
            queue.sync { self.runTeardown() }
        }
    }

    private func runTeardown() {
        stateLock.lock()
        if tornDown {
            stateLock.unlock()
            return
        }
        tornDown = true
        stateLock.unlock()
        teardownOperation()
    }
}
