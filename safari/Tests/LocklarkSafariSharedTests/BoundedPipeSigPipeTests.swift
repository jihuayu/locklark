#if canImport(Darwin)
import XCTest
import Darwin
@testable import LocklarkSafariShared

/// Closed-peer and pre-cancelled behaviour of the bounded pipe write, checked
/// without touching the process-wide SIGPIPE disposition.
final class BoundedPipeSigPipeTests: XCTestCase {
    private func currentMask() -> sigset_t? {
        var mask = sigset_t()
        _ = sigemptyset(&mask)
        guard pthread_sigmask(SIG_BLOCK, nil, &mask) == 0 else { return nil }
        return mask
    }

    private func sigPipeBlocked(_ mask: sigset_t) -> Bool {
        var copy = mask
        return sigismember(&copy, SIGPIPE) == 1
    }

    /// A helper that already exited: fixed failure, no SIGPIPE, mask restored.
    func testClosedPeerFailsWithoutSigPipe() throws {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return XCTFail("pipe unavailable") }
        try SocketSupport.makeNonBlocking(fd: fds[1])
        close(fds[0])
        defer { close(fds[1]) }
        let before = try XCTUnwrap(currentMask())
        XCTAssertThrowsError(
            try SocketSupport.writeAllPipeBounded(
                fd: fds[1],
                data: Data(repeating: 0x44, count: 32),
                deadline: DispatchTime.now() + 1,
                isCancelled: { false }
            )
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        let after = try XCTUnwrap(currentMask())
        XCTAssertEqual(sigPipeBlocked(before), sigPipeBlocked(after))
    }

    /// A write that is already cancelled must not emit a single byte.
    func testPreCancelledWriteEmitsNothing() throws {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return XCTFail("pipe unavailable") }
        defer {
            close(fds[0])
            close(fds[1])
        }
        try SocketSupport.makeNonBlocking(fd: fds[1])
        try SocketSupport.makeNonBlocking(fd: fds[0])
        XCTAssertThrowsError(
            try SocketSupport.writeAllPipeBounded(
                fd: fds[1],
                data: Data(repeating: 0x45, count: 64),
                deadline: DispatchTime.now() + 1,
                isCancelled: { true }
            )
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        var buffer = [UInt8](repeating: 0, count: 64)
        let readCount = read(fds[0], &buffer, buffer.count)
        XCTAssertEqual(readCount, -1)
        XCTAssertEqual(errno, EAGAIN)
    }
}
#endif
