import XCTest
@testable import LocklarkSecurityLogic

final class SessionBoundaryTests: XCTestCase {
    private let first = VaultTarget(id: "first", revision: "revision-1", field: "password")
    private let second = VaultTarget(id: "second", revision: "revision-2", field: "password")

    private func unlocked() -> SessionBoundary {
        var state = SessionBoundary()
        let token = state.beginUnlock()!
        XCTAssertTrue(state.finishUnlock(token))
        return state
    }

    func testUnlockNeedsAnExplicitCurrentAttempt() {
        var state = SessionBoundary()
        XCTAssertNil(state.capture())
        let old = state.beginUnlock()!
        let current = state.beginUnlock()!
        XCTAssertFalse(state.finishUnlock(old))
        XCTAssertTrue(state.finishUnlock(current))
        XCTAssertNotNil(state.capture())
        XCTAssertFalse(state.finishUnlock(current), "completed unlock must not be reusable")
    }

    func testInactiveInvalidatesAnInFlightSystemAuthentication() {
        var state = SessionBoundary()
        let authentication = state.beginUnlock()!
        state.resignActive()
        state.becomeActive()
        XCTAssertFalse(state.finishUnlock(authentication))
        XCTAssertEqual(state.phase, .locked)
        XCTAssertNil(state.capture())
    }

    func testForegroundDoesNotAutomaticallyRestartAuthentication() {
        var state = unlocked()
        state.resignActive()
        XCTAssertNil(state.beginUnlock())
        state.becomeActive()
        XCTAssertEqual(state.phase, .locked)
        XCTAssertNil(state.capture())
    }

    func testSelectionChangeRejectsLateDisclosure() {
        var state = unlocked()
        state.select(first)
        let pending = state.capture()!
        state.select(second)
        XCTAssertFalse(state.permits(pending))
        XCTAssertTrue(state.permits(state.capture()!))
    }

    func testSameItemWithNewRevisionRejectsLateDisclosure() {
        var state = unlocked()
        state.select(first)
        let pending = state.capture()!
        state.select(VaultTarget(id: first.id, revision: "new-revision", field: first.field))
        XCTAssertFalse(state.permits(pending))
    }

    func testFieldChangeRejectsLateDisclosure() {
        var state = unlocked()
        state.select(first)
        let pending = state.capture()!
        state.select(VaultTarget(id: first.id, revision: first.revision, field: "notes"))
        XCTAssertFalse(state.permits(pending))
    }

    func testReselectingTheSameTargetInvalidatesOlderWork() {
        var state = unlocked()
        state.select(first)
        let pending = state.capture()!
        state.select(first)
        XCTAssertFalse(state.permits(pending))
    }

    func testLockAndAWholeNewSessionRejectOldResults() {
        var state = unlocked()
        state.select(first)
        let pending = state.capture()!
        state.lock()
        XCTAssertFalse(state.permits(pending))
        let current = state.beginUnlock()!
        XCTAssertTrue(state.finishUnlock(current))
        state.select(first)
        XCTAssertFalse(state.permits(pending))
    }
}
