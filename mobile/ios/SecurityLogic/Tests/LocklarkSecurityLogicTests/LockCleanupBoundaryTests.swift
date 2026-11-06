import XCTest
@testable import LocklarkSecurityLogic

final class LockCleanupBoundaryTests: XCTestCase {
    func testFreshCaptureWaitsForAllLifecycleCleanup() {
        var cleanup = LockCleanupBoundary()
        let old = cleanup.begin()
        let current = cleanup.begin()
        XCTAssertTrue(cleanup.isPending)
        XCTAssertTrue(cleanup.finish(old))
        XCTAssertTrue(cleanup.isPending)
        XCTAssertFalse(cleanup.finish(old), "duplicate old callback cannot retire a new cleanup")
        XCTAssertTrue(cleanup.isPending)
        XCTAssertTrue(cleanup.finish(current))
        XCTAssertFalse(cleanup.isPending)
    }
}
