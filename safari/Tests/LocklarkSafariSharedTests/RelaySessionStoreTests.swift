import XCTest
@testable import LocklarkSafariShared

/// Bounded reservation state machine: capacity accounting, duplicate refusal,
/// exact-profile cancellation, and - with a factory that blocks - the guarantee
/// that a late session is never bound after close/closeAll and is closed
/// exactly once. Every test is pure Swift with an injected factory: no helper
/// process is launched and no code signature is claimed.
final class RelaySessionStoreTests: XCTestCase {
    private final class FakeSession {
        private let lock = NSLock()
        private var closeCount = 0

        func close() {
            lock.lock()
            closeCount += 1
            lock.unlock()
        }

        var closes: Int {
            lock.lock()
            defer { lock.unlock() }
            return closeCount
        }
    }

    /// Session factory whose creation can be suspended, so a test can close,
    /// revoke or restart while an `open` is still in flight.
    private final class GatedFactory {
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var gated = false
        private var made: [FakeSession] = []

        func setGated(_ value: Bool) {
            lock.lock()
            gated = value
            lock.unlock()
        }

        func make(profile: String?) throws -> FakeSession {
            lock.lock()
            let block = gated
            lock.unlock()
            if block {
                entered.signal()
                _ = release.wait(timeout: .now() + 10)
            }
            let session = FakeSession()
            lock.lock()
            made.append(session)
            lock.unlock()
            return session
        }

        var createdCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return made.count
        }

        var last: FakeSession? {
            lock.lock()
            defer { lock.unlock() }
            return made.last
        }
    }

    private final class ResultBox<Value> {
        private let lock = NSLock()
        private var value: Value?

        func set(_ new: Value) {
            lock.lock()
            value = new
            lock.unlock()
        }

        var get: Value? {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
    }

    private let tokenA = "0123456789abcdef0123456789abcdef"
    private let tokenB = "fedcba9876543210fedcba9876543210"

    private func token(_ index: Int) -> String {
        String(format: "%032x", index + 1)
    }

    private func makeStore(
        _ factory: GatedFactory,
        capacity: Int = RelayLimits.maxConnections,
        openingTTL: TimeInterval = RelayLimits.openingReservationTTL,
        sessionTTL: TimeInterval = RelayLimits.sessionTTL,
        now: @escaping () -> Date = { Date() }
    ) -> RelaySessionStore<FakeSession> {
        RelaySessionStore<FakeSession>(
            capacity: capacity,
            openingTTL: openingTTL,
            sessionTTL: sessionTTL,
            now: now,
            make: { profile in try factory.make(profile: profile) },
            close: { session in session.close() }
        )
    }

    /// Starts an `open` that suspends inside the factory and waits until its
    /// reservation is observable.
    private func startBlockedOpen(
        _ store: RelaySessionStore<FakeSession>,
        factory: GatedFactory,
        token: String,
        profile: String?,
        result: ResultBox<RelaySessionStore<FakeSession>.OpenResult>,
        done: XCTestExpectation
    ) {
        factory.setGated(true)
        DispatchQueue.global().async {
            result.set(store.open(token: token, profile: profile))
            done.fulfill()
        }
        XCTAssertEqual(
            factory.entered.wait(timeout: .now() + 5),
            .success,
            "factory never reached the blocking point"
        )
    }

    func testCloseCancelsOpeningAndLateSessionIsNeverBound() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "open finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenA,
            profile: "Profile A",
            result: result,
            done: done
        )
        XCTAssertEqual(store.openingCount, 1)
        XCTAssertEqual(store.readyCount, 0)
        XCTAssertEqual(
            store.close(token: tokenA, profile: "Profile A"),
            .cancelledOpening
        )
        XCTAssertEqual(store.openingCount, 0)
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .revoked)
        XCTAssertEqual(store.totalCount, 0)
        XCTAssertEqual(factory.createdCount, 1)
        XCTAssertEqual(factory.last?.closes, 1)
    }

    func testCloseAllDuringOpenRevokesAndClosesLateSessionOnce() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "open finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenA,
            profile: nil,
            result: result,
            done: done
        )
        store.closeAll()
        XCTAssertTrue(store.closed)
        XCTAssertEqual(store.totalCount, 0)
        XCTAssertEqual(store.open(token: tokenB, profile: nil), .closed)
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .closed)
        XCTAssertEqual(factory.last?.closes, 1)
        XCTAssertNil(store.session(token: tokenA, profile: nil))
    }

    func testCloseAllClosesReadySessionsExactlyOnce() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .opened)
        XCTAssertEqual(store.open(token: tokenB, profile: "Profile B"), .opened)
        let unprofiled = store.session(token: tokenA, profile: nil)
        let profiled = store.session(token: tokenB, profile: "Profile B")
        XCTAssertNotNil(unprofiled)
        XCTAssertNotNil(profiled)
        store.closeAll()
        store.closeAll()
        XCTAssertEqual(unprofiled?.closes, 1)
        XCTAssertEqual(profiled?.closes, 1)
        XCTAssertEqual(store.totalCount, 0)
        XCTAssertEqual(store.close(token: tokenA, profile: nil), .closedStore)
        XCTAssertEqual(store.sweepExpired(), 0)
    }

    func testDuplicateOpenIsRefusedInsteadOfReplacing() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: "Profile A"), .opened)
        let original = store.session(token: tokenA, profile: "Profile A")
        XCTAssertEqual(
            store.open(token: tokenA, profile: "Profile A"),
            .duplicateToken
        )
        XCTAssertEqual(
            store.open(token: tokenA, profile: "Profile B"),
            .duplicateToken
        )
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .duplicateToken)
        XCTAssertEqual(factory.createdCount, 1)
        XCTAssertTrue(
            store.session(token: tokenA, profile: "Profile A") === original
        )
        XCTAssertNil(store.session(token: tokenA, profile: "Profile B"))
        XCTAssertNil(store.session(token: tokenA, profile: nil))
        XCTAssertEqual(store.totalCount, 1)
    }

    func testDuplicateOpenDuringOpeningIsRefused() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "open finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenA,
            profile: nil,
            result: result,
            done: done
        )
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .duplicateToken)
        XCTAssertEqual(
            store.open(token: tokenA, profile: "Profile B"),
            .duplicateToken
        )
        XCTAssertEqual(factory.createdCount, 0)
        XCTAssertEqual(store.openingCount, 1)
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .opened)
        XCTAssertEqual(store.readyCount, 1)
    }

    func testMismatchedProfileCancelsAndClosesNothing() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: "Profile A"), .opened)
        XCTAssertEqual(
            store.close(token: tokenA, profile: "Profile B"),
            .profileMismatch
        )
        XCTAssertEqual(store.close(token: tokenA, profile: nil), .profileMismatch)
        XCTAssertEqual(store.close(token: tokenB, profile: nil), .notFound)
        XCTAssertEqual(store.readyCount, 1)
        XCTAssertNotNil(store.session(token: tokenA, profile: "Profile A"))

        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "opening finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenB,
            profile: "Profile B",
            result: result,
            done: done
        )
        XCTAssertEqual(
            store.close(token: tokenB, profile: "Profile A"),
            .profileMismatch
        )
        XCTAssertEqual(store.close(token: tokenB, profile: nil), .profileMismatch)
        XCTAssertEqual(store.openingCount, 1)
        XCTAssertEqual(
            store.close(token: tokenB, profile: "Profile B"),
            .cancelledOpening
        )
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .revoked)
        XCTAssertEqual(factory.last?.closes, 1)
    }

    func testCapacityCountsOpeningsAndReadySessions() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        var results: [ResultBox<RelaySessionStore<FakeSession>.OpenResult>] = []
        var waits: [XCTestExpectation] = []
        for index in 0..<RelayLimits.maxConnections {
            let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
            let done = expectation(description: "open \(index)")
            results.append(result)
            waits.append(done)
            startBlockedOpen(
                store,
                factory: factory,
                token: token(index),
                profile: nil,
                result: result,
                done: done
            )
        }
        XCTAssertEqual(RelayLimits.maxConnections, 8)
        XCTAssertEqual(store.openingCount, 8)
        XCTAssertEqual(store.readyCount, 0)
        XCTAssertEqual(store.totalCount, 8)
        // The ninth open is refused before the factory is ever called.
        XCTAssertEqual(store.open(token: token(99), profile: nil), .capacityExceeded)
        XCTAssertEqual(factory.createdCount, 0)
        // Cancelling one in-flight reservation frees exactly one slot.
        XCTAssertEqual(store.close(token: token(0), profile: nil), .cancelledOpening)
        XCTAssertEqual(store.totalCount, 7)
        for _ in 0..<RelayLimits.maxConnections { factory.release.signal() }
        for done in waits { wait(for: [done], timeout: 10) }
        XCTAssertEqual(results[0].get, .revoked)
        for index in 1..<RelayLimits.maxConnections {
            XCTAssertEqual(results[index].get, .opened)
        }
        XCTAssertEqual(store.readyCount, 7)
        XCTAssertEqual(store.totalCount, 7)
        // Ready sessions count against the same bound.
        factory.setGated(false)
        XCTAssertEqual(store.open(token: token(99), profile: nil), .opened)
        XCTAssertEqual(store.totalCount, 8)
        XCTAssertEqual(store.open(token: token(100), profile: nil), .capacityExceeded)
        XCTAssertEqual(store.totalCount, 8)
    }

    func testOldAcceptedLeaseCannotBindAfterRestart() {
        let factory = GatedFactory()
        let first = makeStore(factory)
        let epochs = StoreEpochTable(first)
        let lease = epochs.capture()
        XCTAssertTrue(lease.store === first)
        XCTAssertTrue(epochs.isCurrent(lease.epoch))

        // stop: the current store is revoked and permanently closed.
        lease.store.closeAll()
        // restart: a brand-new store under a new generation.
        let second = makeStore(factory)
        XCTAssertTrue(epochs.replace(with: second) === first)
        XCTAssertFalse(epochs.isCurrent(lease.epoch))
        XCTAssertEqual(epochs.capture().epoch, lease.epoch + 1)
        XCTAssertTrue(epochs.isCurrent(epochs.capture().epoch))

        // The worker accepted before the restart still holds the old lease,
        // and that store refuses every further open.
        XCTAssertEqual(lease.store.open(token: tokenA, profile: nil), .closed)
        XCTAssertEqual(lease.store.totalCount, 0)
        // The new store is independent and accepts the same token.
        XCTAssertEqual(second.open(token: tokenA, profile: nil), .opened)
        XCTAssertNotNil(second.session(token: tokenA, profile: nil))
        XCTAssertEqual(first.totalCount, 0)
    }

    // MARK: - Conditional (identity-guarded) discard

    /// A helper failure carries the session it captured. If the token *and*
    /// profile were closed and reopened in the meantime, the stale failure must
    /// refuse to touch the replacement binding.
    func testConditionalDiscardRefusesReplacementAfterCloseReopen() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: "Profile A"), .opened)
        guard let stale = store.session(token: tokenA, profile: "Profile A") else {
            return XCTFail("first session was not bound")
        }
        XCTAssertEqual(
            store.close(token: tokenA, profile: "Profile A"),
            .closedSession
        )
        XCTAssertEqual(stale.closes, 1)
        // Same token and same profile: a new helper owns the slot now.
        XCTAssertEqual(store.open(token: tokenA, profile: "Profile A"), .opened)
        guard let replacement = store.session(
            token: tokenA,
            profile: "Profile A"
        ) else { return XCTFail("replacement session was not bound") }
        XCTAssertFalse(replacement === stale)

        // The old helper reports unusable: only its own binding may go.
        XCTAssertFalse(
            store.discard(
                token: tokenA,
                profile: "Profile A",
                matching: { $0 === stale }
            )
        )
        XCTAssertTrue(
            store.session(token: tokenA, profile: "Profile A") === replacement
        )
        XCTAssertEqual(replacement.closes, 0)
        XCTAssertEqual(stale.closes, 1)
        XCTAssertEqual(store.readyCount, 1)
        XCTAssertEqual(store.totalCount, 1)
    }

    /// The dead helper's own binding is removed and closed exactly once, and
    /// the capacity slot is free immediately instead of being held until the
    /// session TTL would expire it.
    func testConditionalDiscardFreesMatchingDeadBindingOnce() {
        let factory = GatedFactory()
        let store = makeStore(factory, capacity: 1)
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .opened)
        guard let dead = store.session(token: tokenA, profile: nil) else {
            return XCTFail("session was not bound")
        }
        // One slot, taken by the session that is about to die.
        XCTAssertEqual(store.open(token: tokenB, profile: nil), .capacityExceeded)
        XCTAssertTrue(
            store.discard(token: tokenA, profile: nil, matching: { $0 === dead })
        )
        XCTAssertEqual(dead.closes, 1)
        XCTAssertEqual(store.readyCount, 0)
        XCTAssertEqual(store.totalCount, 0)
        // The slot is available at once: no TTL sweep is needed.
        XCTAssertEqual(store.open(token: tokenB, profile: nil), .opened)
        XCTAssertEqual(store.totalCount, 1)
        guard let live = store.session(token: tokenB, profile: nil) else {
            return XCTFail("replacement session was not bound")
        }
        // A repeated failure report for the same dead session closes nothing.
        XCTAssertFalse(
            store.discard(token: tokenA, profile: nil, matching: { $0 === dead })
        )
        XCTAssertEqual(dead.closes, 1)
        XCTAssertEqual(live.closes, 0)
        XCTAssertEqual(store.readyCount, 1)
        // The unconditional variant stays available and behaves as before.
        XCTAssertTrue(store.discard(token: tokenB, profile: nil))
        XCTAssertEqual(live.closes, 1)
        XCTAssertEqual(store.readyCount, 0)
    }

    /// A profile mismatch never resolves a session, so the guard must not run,
    /// remove or close anything even when it would accept the session.
    func testConditionalDiscardWithMismatchedProfileClosesNothing() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: "Profile A"), .opened)
        guard let session = store.session(
            token: tokenA,
            profile: "Profile A"
        ) else { return XCTFail("session was not bound") }
        XCTAssertFalse(
            store.discard(token: tokenA, profile: "Profile B", matching: { _ in true })
        )
        XCTAssertFalse(
            store.discard(token: tokenA, profile: nil, matching: { _ in true })
        )
        XCTAssertFalse(
            store.discard(token: tokenB, profile: "Profile A", matching: { _ in true })
        )
        XCTAssertEqual(session.closes, 0)
        XCTAssertEqual(store.readyCount, 1)
        XCTAssertTrue(
            store.session(token: tokenA, profile: "Profile A") === session
        )
        // The exact match still wins afterwards.
        XCTAssertTrue(
            store.discard(
                token: tokenA,
                profile: "Profile A",
                matching: { $0 === session }
            )
        )
        XCTAssertEqual(session.closes, 1)
        XCTAssertEqual(store.readyCount, 0)
    }

    /// A request still in flight across teardown reports a failure afterwards:
    /// the binding is already gone and closed once, so the guarded discard must
    /// be refused instead of closing the session twice.
    func testConditionalDiscardAfterTeardownClosesNothing() {
        let factory = GatedFactory()
        let store = makeStore(factory)
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .opened)
        guard let session = store.session(token: tokenA, profile: nil) else {
            return XCTFail("session was not bound")
        }
        store.closeAll()
        XCTAssertEqual(session.closes, 1)
        XCTAssertFalse(
            store.discard(token: tokenA, profile: nil, matching: { $0 === session })
        )
        XCTAssertEqual(session.closes, 1)
        XCTAssertEqual(store.readyCount, 0)
    }

    func testSweepExpiresReadySessionsAndStaleOpenings() {
        let factory = GatedFactory()
        var clock = Date(timeIntervalSince1970: 1_000)
        let store = makeStore(
            factory,
            capacity: 4,
            openingTTL: 10,
            sessionTTL: 60,
            now: { clock }
        )
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .opened)
        let old = factory.last
        clock = clock.addingTimeInterval(31)
        XCTAssertEqual(store.open(token: tokenB, profile: nil), .opened)
        let fresh = factory.last
        clock = clock.addingTimeInterval(31)
        XCTAssertEqual(store.sweepExpired(), 1)
        XCTAssertEqual(old?.closes, 1)
        XCTAssertEqual(fresh?.closes, 0)
        XCTAssertEqual(store.readyCount, 1)
        XCTAssertNotNil(store.session(token: tokenB, profile: nil))
        XCTAssertNil(store.session(token: tokenA, profile: nil))

        // An opening reservation past its shorter TTL is released, so the
        // still-blocked open refuses to bind and closes its session once.
        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "late opening finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenA,
            profile: nil,
            result: result,
            done: done
        )
        XCTAssertEqual(store.openingCount, 1)
        clock = clock.addingTimeInterval(11)
        XCTAssertEqual(store.sweepExpired(), 0)
        XCTAssertEqual(store.openingCount, 0)
        XCTAssertEqual(store.totalCount, 1)
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .revoked)
        XCTAssertEqual(store.readyCount, 1)
        XCTAssertEqual(store.openingCount, 0)
        XCTAssertEqual(factory.last?.closes, 1)
    }

    /// Clock shared with a background `open`, so a test can advance time while
    /// the factory is blocked without a data race on the stored date.
    private final class LockedClock {
        private let lock = NSLock()
        private var value: Date

        init(_ start: Date) { value = start }

        var now: Date {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func advance(_ seconds: TimeInterval) {
            lock.lock()
            value = value.addingTimeInterval(seconds)
            lock.unlock()
        }
    }

    func testLateFactoryAfterOpeningTTLWithoutSweepIsRevokedAndClosedOnce() {
        let factory = GatedFactory()
        let clock = LockedClock(Date(timeIntervalSince1970: 5_000))
        let store = makeStore(
            factory,
            openingTTL: 10,
            sessionTTL: 60,
            now: { clock.now }
        )
        let result = ResultBox<RelaySessionStore<FakeSession>.OpenResult>()
        let done = expectation(description: "late open finished")
        startBlockedOpen(
            store,
            factory: factory,
            token: tokenA,
            profile: nil,
            result: result,
            done: done
        )
        XCTAssertEqual(store.openingCount, 1)
        // Past the opening TTL while the factory is still blocked, and no
        // sweep has run: the completion itself must refuse to bind.
        clock.advance(11)
        factory.release.signal()
        wait(for: [done], timeout: 10)
        XCTAssertEqual(result.get, .revoked)
        XCTAssertEqual(store.readyCount, 0)
        XCTAssertEqual(store.openingCount, 0)
        XCTAssertEqual(store.totalCount, 0)
        XCTAssertEqual(factory.createdCount, 1)
        XCTAssertEqual(factory.last?.closes, 1)
    }

    func testLookupAfterSessionTTLClosesAndRefusesWithoutSweep() {
        let factory = GatedFactory()
        let clock = LockedClock(Date(timeIntervalSince1970: 9_000))
        let store = makeStore(factory, sessionTTL: 30, now: { clock.now })
        XCTAssertEqual(store.open(token: tokenA, profile: nil), .opened)
        let session = factory.last
        XCTAssertNotNil(store.session(token: tokenA, profile: nil))
        clock.advance(30)
        XCTAssertNil(store.session(token: tokenA, profile: nil))
        XCTAssertEqual(session?.closes, 1)
        XCTAssertEqual(store.readyCount, 0)
        // A second lookup must not close the same session twice.
        XCTAssertNil(store.session(token: tokenA, profile: nil))
        XCTAssertEqual(session?.closes, 1)
        XCTAssertEqual(store.close(token: tokenA, profile: nil), .notFound)
    }
}
