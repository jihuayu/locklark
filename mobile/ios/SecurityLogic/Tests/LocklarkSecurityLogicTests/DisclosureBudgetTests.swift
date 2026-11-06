import XCTest
@testable import LocklarkSecurityLogic

final class DisclosureBudgetTests: XCTestCase {
    func testOriginalWindowNeverRestartsAtPresentation() {
        let budget = DisclosureBudget(from: 1_000, until: 4_000, issuedWall: 3_500)!
        XCTAssertTrue(budget.permits(wallNow: 3_999, elapsedMilliseconds: 499))
        XCTAssertFalse(budget.permits(wallNow: 4_000, elapsedMilliseconds: 499))
        XCTAssertFalse(budget.permits(wallNow: 3_999, elapsedMilliseconds: 500))
    }

    func testForwardWallClockRejectsWhenMonotonicClockHasNotAdvanced() {
        let budget = DisclosureBudget(from: 1_000, until: 4_000, issuedWall: 2_000)!
        XCTAssertFalse(budget.permits(wallNow: 4_000, elapsedMilliseconds: 0))
    }

    func testBackwardWallClockCannotExtendDisclosure() {
        let budget = DisclosureBudget(from: 1_000, until: 20_000, issuedWall: 2_000)!
        XCTAssertFalse(budget.permits(wallNow: 1_999, elapsedMilliseconds: 1))
        XCTAssertFalse(budget.permits(wallNow: 2_001, elapsedMilliseconds: 15_000))
    }

    func testAbsoluteDisplayCapIsFifteenSeconds() {
        let budget = DisclosureBudget(from: 0, until: 100_000, issuedWall: 1_000)!
        XCTAssertTrue(budget.permits(wallNow: 15_999, elapsedMilliseconds: 14_999))
        XCTAssertFalse(budget.permits(wallNow: 16_000, elapsedMilliseconds: 15_000))
    }

    func testInvalidAndOverflowingWindowsAreRefused() {
        XCTAssertNil(DisclosureBudget(from: 10, until: 10, issuedWall: 10))
        XCTAssertNil(DisclosureBudget(from: 11, until: 20, issuedWall: 10))
        XCTAssertNil(DisclosureBudget(from: Int64.min, until: Int64.max, issuedWall: Int64.min))
        let budget = DisclosureBudget(from: 0, until: 10, issuedWall: 1)!
        XCTAssertFalse(budget.permits(wallNow: 2, elapsedMilliseconds: -1))
    }
}
