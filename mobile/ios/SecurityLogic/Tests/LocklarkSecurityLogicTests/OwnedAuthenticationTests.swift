import XCTest
@testable import LocklarkSecurityLogic

final class OwnedAuthenticationTests: XCTestCase {
    func testOwnedPromptMayFinishInactiveButNeverEnterVaultUntilActive() {
        var screen = SessionBoundary()
        var auth = OwnedAuthentication()
        let token = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 0)!
        screen.resignActive()
        XCTAssertEqual(screen.phase, .locked)
        XCTAssertTrue(auth.systemSucceeded(token, monotonicNow: 1_000))
        XCTAssertFalse(auth.consume(token, isActive: false, monotonicNow: 1_001))
        screen.becomeActive()
        XCTAssertTrue(auth.consume(token, isActive: screen.isActive, monotonicNow: 1_002))
        XCTAssertFalse(auth.consume(token, isActive: true, monotonicNow: 1_003))
        XCTAssertEqual(screen.phase, .locked, "preauthentication does not itself unlock a vault")
    }

    func testRealBackgroundCancelsLateSystemSuccess() {
        var auth = OwnedAuthentication()
        let token = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 0)!
        auth.cancel()
        XCTAssertFalse(auth.systemSucceeded(token, monotonicNow: 1))
        XCTAssertFalse(auth.consume(token, isActive: true, monotonicNow: 2))
    }

    func testOldCallbackCannotAuthorizeANewExplicitAttempt() {
        var auth = OwnedAuthentication()
        let old = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 0)!
        auth.cancel()
        let current = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 100)!
        XCTAssertFalse(auth.systemSucceeded(old, monotonicNow: 101))
        XCTAssertFalse(auth.ready(current, isActive: true, monotonicNow: 101))
        XCTAssertTrue(auth.systemSucceeded(current, monotonicNow: 102))
        XCTAssertTrue(auth.consume(current, isActive: true, monotonicNow: 103))
    }

    func testAuthorizationHasAShortOriginalMonotonicDeadline() {
        var auth = OwnedAuthentication()
        let token = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 0)!
        XCTAssertTrue(auth.systemSucceeded(token, monotonicNow: 2_000))
        XCTAssertTrue(auth.ready(token, isActive: true, monotonicNow: 11_999))
        XCTAssertFalse(auth.ready(token, isActive: true, monotonicNow: 12_000))
        XCTAssertFalse(auth.ready(token, isActive: true, monotonicNow: 1_999))
    }

    func testPromptItselfIsBoundedAndCannotFinishTwice() {
        var auth = OwnedAuthentication()
        let token = auth.begin(vaultLocked: true, isActive: true, monotonicNow: 0)!
        XCTAssertFalse(auth.systemSucceeded(token, monotonicNow: 60_000))
        XCTAssertFalse(auth.systemSucceeded(token, monotonicNow: -1))
        XCTAssertTrue(auth.systemSucceeded(token, monotonicNow: 59_999))
        XCTAssertFalse(auth.systemSucceeded(token, monotonicNow: 59_999))
    }

    func testInactiveExceptionNeverAppliesToAnUnlockedSession() {
        var auth = OwnedAuthentication()
        XCTAssertNil(auth.begin(vaultLocked: false, isActive: true, monotonicNow: 0))
        XCTAssertNil(auth.begin(vaultLocked: true, isActive: false, monotonicNow: 0))
    }
}
