import XCTest
@testable import LocklarkSafariShared

/// Revocation propagation and per-instance queue identity of the stdin gate.
final class SerializedPipeWriterIsolationTests: XCTestCase {
    private func waitFor(_ event: String, in log: GateEventLog) -> Bool {
        let limit = Date().addingTimeInterval(2)
        while Date() < limit {
            if log.snapshot().contains(event) { return true }
            Thread.sleep(forTimeInterval: 0.002)
        }
        return log.snapshot().contains(event)
    }

    func testRevocationStopsInFlightWriteWithoutTearingDown() throws {
        let log = GateEventLog()
        let started = DispatchSemaphore(value: 0)
        let observed = DispatchSemaphore(value: 0)
        let gate = SerializedPipeWriter(
            fd: 11,
            write: { _, _, _, isCancelled in
                started.signal()
                while !isCancelled() { Thread.sleep(forTimeInterval: 0.002) }
                log.add("cancelled")
                observed.signal()
                throw RelayError.unavailable
            },
            teardown: { log.add("teardown") }
        )
        DispatchQueue.global().async {
            do { try gate.write(Data([0x04])) } catch { log.add("write-failed") }
        }
        XCTAssertEqual(started.wait(timeout: .now() + 2), .success)
        gate.revoke()
        XCTAssertEqual(observed.wait(timeout: .now() + 2), .success)
        // Revocation alone stops the write; teardown is still the closer's job.
        XCTAssertFalse(log.snapshot().contains("teardown"))
        gate.close()
        XCTAssertEqual(log.snapshot().filter { $0 == "teardown" }.count, 1)
    }

    func testCloseFromAnotherGateQueueNeverTearsDownInFlightWrite() throws {
        let log = GateEventLog()
        let bStarted = DispatchSemaphore(value: 0)
        let releaseB = DispatchSemaphore(value: 0)
        let gateB = SerializedPipeWriter(
            fd: 21,
            write: { _, _, _, _ in
                log.add("b-write-start")
                bStarted.signal()
                _ = releaseB.wait(timeout: .now() + 2)
                log.add("b-write-end")
            },
            teardown: { log.add("b-teardown") }
        )
        let aClosedB = DispatchSemaphore(value: 0)
        let gateA = SerializedPipeWriter(
            fd: 22,
            write: { _, _, _, _ in
                // A close issued from *another* gate's queue must not be taken
                // for B's own queue: it may not tear B down inline.
                gateB.close(wait: 0.05)
                log.add("a-close-b-returned")
                aClosedB.signal()
            },
            teardown: { log.add("a-teardown") }
        )
        DispatchQueue.global().async { try? gateB.write(Data([0x05])) }
        XCTAssertEqual(bStarted.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async { try? gateA.write(Data([0x06])) }
        XCTAssertEqual(aClosedB.wait(timeout: .now() + 2), .success)
        XCTAssertFalse(log.snapshot().contains("b-teardown"))
        XCTAssertFalse(log.snapshot().contains("b-write-end"))
        releaseB.signal()
        XCTAssertTrue(waitFor("b-teardown", in: log))
        let events = log.snapshot()
        let writeEnd = try XCTUnwrap(events.firstIndex(of: "b-write-end"))
        let teardown = try XCTUnwrap(events.firstIndex(of: "b-teardown"))
        XCTAssertLessThan(writeEnd, teardown)
        XCTAssertEqual(events.filter { $0 == "b-teardown" }.count, 1)
        XCTAssertFalse(events.contains("a-teardown"))
    }

    func testThrowingWriteDoesNotPoisonClose() throws {
        let log = GateEventLog()
        let gate = SerializedPipeWriter(
            fd: 12,
            write: { _, _, _, _ in throw RelayError.unavailable },
            teardown: { log.add("teardown") }
        )
        XCTAssertThrowsError(try gate.write(Data([0x08]))) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        gate.close()
        gate.close()
        XCTAssertEqual(log.snapshot(), ["teardown"])
    }
}
