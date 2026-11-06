import XCTest
@testable import LocklarkSecurityLogic

final class ExposureBoundaryTests: XCTestCase {
    func testOldTimerAfterNewDisclosureCannotClearTheNewValue() {
        var exposure = ExposureBoundary()
        let old = exposure.begin()
        exposure.cancel() // old timer's sleep has been cancelled but may resume
        let current = exposure.begin()
        XCTAssertFalse(exposure.expire(old), "late old timer cannot own a new disclosure")
        XCTAssertTrue(exposure.owns(current))
        XCTAssertTrue(exposure.expire(current))
        XCTAssertFalse(exposure.owns(current))
    }
}
