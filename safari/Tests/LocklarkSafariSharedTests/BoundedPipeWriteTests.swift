#if canImport(Darwin)
import XCTest
import Darwin
@testable import LocklarkSafariShared

/// Bounded, non-blocking pipe writes for the helper's stdin (Darwin only).
final class BoundedPipeWriteTests: XCTestCase {
    private final class Flag {
        private let lock = NSLock()
        private var set = false
        var isSet: Bool {
            lock.lock()
            defer { lock.unlock() }
            return set
        }
        func raise() {
            lock.lock()
            set = true
            lock.unlock()
        }
    }

    private func makePipe(nonBlocking: Bool = true) throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { throw RelayError.unavailable }
        if nonBlocking {
            try SocketSupport.makeNonBlocking(fd: fds[1])
        }
        return fds
    }

    private func elapsedSeconds(since start: DispatchTime) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1e9
    }

    /// No reader at all: the absolute deadline, not a blocking write, ends it.
    func testPipeBackpressureFailsAtDeadline() throws {
        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        let start = DispatchTime.now()
        XCTAssertThrowsError(
            try SocketSupport.writeAllPipeBounded(
                fd: fds[1],
                data: Data(repeating: 0x41, count: 4 * 1024 * 1024),
                deadline: start + 0.3,
                isCancelled: { false }
            )
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        XCTAssertLessThan(elapsedSeconds(since: start), 2)
    }

    /// Revocation while the helper is not reading ends the write promptly.
    func testCancellationUnblocksStalledWrite() throws {
        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        let flag = Flag()
        let start = DispatchTime.now()
        let finished = expectation(description: "cancelled write fails")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            do {
                try SocketSupport.writeAllPipeBounded(
                    fd: fds[1],
                    data: Data(repeating: 0x42, count: 4 * 1024 * 1024),
                    deadline: DispatchTime.now() + 10,
                    isCancelled: { flag.isSet }
                )
                XCTFail("a stalled write must not report success")
            } catch {
                XCTAssertEqual(error as? RelayError, .unavailable)
            }
        }
        Thread.sleep(forTimeInterval: 0.05)
        flag.raise()
        wait(for: [finished], timeout: 5)
        XCTAssertLessThan(elapsedSeconds(since: start), 2)
    }

    /// The bounded API refuses a blocking descriptor instead of trusting it.
    func testBlockingDescriptorIsRefused() throws {
        let fds = try makePipe(nonBlocking: false)
        defer {
            close(fds[0])
            close(fds[1])
        }
        XCTAssertThrowsError(
            try SocketSupport.writeAllPipeBounded(
                fd: fds[1],
                data: Data([0x43]),
                deadline: DispatchTime.now() + 1,
                isCancelled: { false }
            )
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
    }
}
#endif
