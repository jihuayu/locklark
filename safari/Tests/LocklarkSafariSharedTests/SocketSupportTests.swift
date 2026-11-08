#if canImport(Darwin)
import XCTest
import Darwin
@testable import LocklarkSafariShared

/// Thread-local SIGPIPE hygiene for the relay's write path.
///
/// The XCTest host's process-wide SIGPIPE disposition is deliberately left
/// alone here (see `TestProbe/`: a standalone executable covers the
/// closed-peer/default-disposition cases). These tests only prove that the
/// caller's exact thread signal mask is preserved and that checked socket
/// setup failures surface as the fixed error.
final class SocketSupportTests: XCTestCase {
    private let comparedSignals: [Int32] = [
        SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, SIGALRM, SIGCHLD,
    ]

    private func currentMask() -> sigset_t? {
        var mask = sigset_t()
        _ = sigemptyset(&mask)
        guard pthread_sigmask(SIG_BLOCK, nil, &mask) == 0 else { return nil }
        return mask
    }

    private func sameMask(_ lhs: sigset_t, _ rhs: sigset_t) -> Bool {
        for signalNumber in comparedSignals {
            var left = lhs
            var right = rhs
            if sigismember(&left, signalNumber) != sigismember(&right, signalNumber) {
                return false
            }
        }
        return true
    }

    private func isBlocked(_ signalNumber: Int32, in mask: sigset_t) -> Bool {
        var copy = mask
        return sigismember(&copy, signalNumber) == 1
    }

    private func makePipe() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { throw RelayError.unavailable }
        return fds
    }

    func testPipeWriteSucceedsAndRestoresUnblockedMask() throws {
        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        let before = try XCTUnwrap(currentMask())
        try SocketSupport.writeAllPipe(
            fd: fds[1],
            data: Data([0x41, 0x42, 0x43])
        )
        var buffer = [UInt8](repeating: 0, count: 3)
        XCTAssertEqual(read(fds[0], &buffer, buffer.count), 3)
        XCTAssertEqual(buffer, [0x41, 0x42, 0x43])
        let after = try XCTUnwrap(currentMask())
        XCTAssertTrue(sameMask(before, after))
        XCTAssertFalse(isBlocked(SIGPIPE, in: after))
    }

    func testPipeWritePreservesCallerBlockedSIGPIPE() throws {
        var sigpipe = sigset_t()
        _ = sigemptyset(&sigpipe)
        _ = sigaddset(&sigpipe, SIGPIPE)
        var previous = sigset_t()
        _ = sigemptyset(&previous)
        XCTAssertEqual(pthread_sigmask(SIG_BLOCK, &sigpipe, &previous), 0)
        defer { _ = pthread_sigmask(SIG_SETMASK, &previous, nil) }

        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        let before = try XCTUnwrap(currentMask())
        try SocketSupport.writeAllPipe(fd: fds[1], data: Data([0x44]))
        let after = try XCTUnwrap(currentMask())
        XCTAssertTrue(sameMask(before, after))
        XCTAssertTrue(isBlocked(SIGPIPE, in: after))
    }

    func testSocketWriteRoundTripPreservesMask() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            return XCTFail("socketpair unavailable")
        }
        defer {
            close(pair[0])
            close(pair[1])
        }
        XCTAssertNoThrow(try SocketSupport.disableSigPipe(fd: pair[1]))
        let before = try XCTUnwrap(currentMask())
        try SocketSupport.writeAll(fd: pair[1], data: Data([0x55, 0x56]))
        var buffer = [UInt8](repeating: 0, count: 2)
        XCTAssertEqual(read(pair[0], &buffer, buffer.count), 2)
        XCTAssertEqual(buffer, [0x55, 0x56])
        let after = try XCTUnwrap(currentMask())
        XCTAssertTrue(sameMask(before, after))
    }

    /// A non-socket fd cannot take SO_NOSIGPIPE: the failure must be the fixed
    /// error rather than a silent success.
    func testDisableSigPipeIsChecked() throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            return XCTFail("socketpair unavailable")
        }
        defer {
            close(pair[0])
            close(pair[1])
        }
        XCTAssertNoThrow(try SocketSupport.disableSigPipe(fd: pair[0]))

        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        XCTAssertThrowsError(try SocketSupport.disableSigPipe(fd: fds[0])) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
    }
}
#endif
