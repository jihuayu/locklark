import XCTest
@testable import LocklarkSecurityLogic

final class OperationBoundaryTests: XCTestCase {
    func testSearchDuringRevealCannotLeaveBusyOrClearNewOwner() {
        var screen = SessionBoundary()
        let unlock = screen.beginUnlock()!
        XCTAssertTrue(screen.finishUnlock(unlock))
        screen.select(VaultTarget(id: "first", revision: "old", field: "password"))
        let oldScreen = screen.capture()!
        var work = OperationBoundary()
        let oldReveal = work.begin()
        screen.select(nil)
        work.cancel() // navigation invalidates UI work before starting search
        XCTAssertFalse(work.isBusy)
        let search = work.begin()
        XCTAssertFalse(screen.permits(oldScreen), "navigation must discard the late secret")
        XCTAssertFalse(work.finish(oldReveal))
        XCTAssertTrue(work.isBusy, "old disclosure must not clear the search owner")
        XCTAssertTrue(work.finish(search))
        XCTAssertFalse(work.isBusy)
    }

    func testOldSessionCallbackCannotClearANewUnlock() {
        var work = OperationBoundary()
        let old = work.begin()
        work.cancel()
        let unlock = work.begin()
        XCTAssertFalse(work.finish(old))
        XCTAssertTrue(work.isBusy)
        XCTAssertTrue(work.finish(unlock))
        XCTAssertFalse(work.finish(unlock))
    }
}
