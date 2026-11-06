import Foundation
import XCTest
@testable import LocklarkSecurityLogic

final class WorkTicketTests: XCTestCase {
    func testQueuedUnlockCreateAndEditDoNotEnterCoreAfterInactive() throws {
        for kind in ["unlock", "create", "edit"] {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: directory) }
            let file = directory.appendingPathComponent("database")
            let original = Data([1, 2, 3])
            try original.write(to: file)
            let queue = DispatchQueue(label: "blocked-" + kind)
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            queue.async { entered.signal(); release.wait() }
            XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
            let lifecycle = CancellationScope()
            let ticket = lifecycle.ticket()
            var calls = 0, cleanups = 0
            queue.async {
                do {
                    try ticket.run(cleanup: { cleanups += 1 }) {
                        calls += 1
                        try Data([9]).write(to: file)
                    }
                } catch {}
                done.signal()
            }
            lifecycle.invalidate() // the UI's inactive callback wins before dequeue
            release.signal()
            XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
            XCTAssertTrue(calls == 0, "cancelled queued intent must never enter the core")
            XCTAssertTrue(cleanups == 1, "captured buffers need cleanup even before execution")
            XCTAssertTrue(try Data(contentsOf: file) == original, "cancelled queued intent must not mutate the database")
        }
    }

    func testFreshExplicitOperationAfterInvalidationCanRun() throws {
        let scope = CancellationScope()
        let old = scope.ticket()
        scope.invalidate()
        XCTAssertFalse(old.isCurrent)
        let current = scope.ticket()
        XCTAssertTrue(try current.run { true })
    }
}
