import Foundation
import LocalAuthentication

// Created only after the app's explicit, locked OS prompt succeeds. This is a
// single-use, short-lived authorization context, never an unlock-factor cache.
final class SystemAuthenticationAuthorization {
    private let context: LAContext
    private let authenticatedAt: ContinuousClock.Instant
    private let lock = NSLock()
    private var consumed = false

    init(context: LAContext, authenticatedAt: ContinuousClock.Instant) {
        self.context = context
        self.authenticatedAt = authenticatedAt
    }

    func take() throws -> LAContext {
        lock.lock()
        let elapsed = authenticatedAt.duration(to: .now)
        guard !consumed else {
            lock.unlock()
            throw PlatformProtectionError.authenticationCancelled
        }
        consumed = true
        guard elapsed >= .zero, elapsed < .seconds(10) else {
            lock.unlock()
            context.invalidate()
            throw PlatformProtectionError.authenticationCancelled
        }
        lock.unlock()
        return context
    }

    func cancel() {
        lock.lock()
        consumed = true
        lock.unlock()
        context.invalidate()
    }

    deinit { context.invalidate() }
}
