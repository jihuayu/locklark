import XCTest
@testable import LocklarkSafariShared

/// Order-sensitive log for the pure gate tests (no descriptors involved).
final class GateEventLog {
    private let lock = NSLock()
    private var recorded: [String] = []

    func add(_ event: String) {
        lock.lock()
        recorded.append(event)
        lock.unlock()
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }
}

/// Close/revocation semantics of the shared stdin gate: a descriptor is never
/// touched after revocation, never torn down under an in-flight write, and
/// torn down exactly once.
final class SerializedPipeWriterTests: XCTestCase {
    private func waitFor(_ event: String, in log: GateEventLog) -> Bool {
        let limit = Date().addingTimeInterval(2)
        while Date() < limit {
            if log.snapshot().contains(event) { return true }
            Thread.sleep(forTimeInterval: 0.002)
        }
        return log.snapshot().contains(event)
    }

    func testCloseBeforeQueuedWriteNeverCallsWriter() throws {
        let log = GateEventLog()
        let gate = SerializedPipeWriter(
            fd: 7,
            write: { _, _, _, _ in log.add("write") },
            teardown: { log.add("teardown") }
        )
        gate.close()
        XCTAssertThrowsError(try gate.write(Data([0x01]))) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        XCTAssertEqual(log.snapshot(), ["teardown"])
    }

    func testCloseWaitsForInFlightWriteThenTearsDownOnce() throws {
        let log = GateEventLog()
        let started = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let gate = SerializedPipeWriter(
            fd: 9,
            write: { _, _, _, _ in
                log.add("write-start")
                started.signal()
                _ = release.wait(timeout: .now() + 2)
                log.add("write-end")
            },
            teardown: { log.add("teardown") }
        )
        DispatchQueue.global().async { try? gate.write(Data([0x02])) }
        XCTAssertEqual(started.wait(timeout: .now() + 2), .success)
        let closed = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            gate.close(wait: 1)
            closed.signal()
        }
        // close waits for the write; it never closes the descriptor under it.
        XCTAssertEqual(closed.wait(timeout: .now() + 0.05), .timedOut)
        XCTAssertEqual(log.snapshot(), ["write-start"])
        release.signal()
        XCTAssertEqual(closed.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(log.snapshot(), ["write-start", "write-end", "teardown"])
        gate.close()
        gate.close()
        XCTAssertEqual(log.snapshot(), ["write-start", "write-end", "teardown"])
        XCTAssertThrowsError(try gate.write(Data([0x03])))
        XCTAssertEqual(log.snapshot(), ["write-start", "write-end", "teardown"])
    }

    func testReentrantCloseFromWriteOperationNeverClosesUnderIt() throws {
        let log = GateEventLog()
        var gate: SerializedPipeWriter!
        gate = SerializedPipeWriter(
            fd: 31,
            write: { _, _, _, _ in
                log.add("write-start")
                gate.close(wait: 0.2)
                log.add("close-returned")
                log.add("write-end")
            },
            teardown: { log.add("teardown") }
        )
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            try? gate.write(Data([0x07]))
            done.signal()
        }
        XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
        XCTAssertTrue(waitFor("teardown", in: log))
        let events = log.snapshot()
        let end = try XCTUnwrap(events.firstIndex(of: "write-end"))
        let teardown = try XCTUnwrap(events.firstIndex(of: "teardown"))
        XCTAssertLessThan(end, teardown)
        XCTAssertEqual(events.filter { $0 == "teardown" }.count, 1)
    }
}
