#if canImport(Darwin)
import XCTest
import Darwin
@testable import LocklarkSafariShared

/// Closed-peer and pre-cancelled behaviour of the pipe write APIs, checked
/// without touching the process-wide SIGPIPE disposition.
///
/// The XCTest host is multithreaded, so a thread-scoped mask alone is not a
/// process safety argument here: these tests cover the per-descriptor
/// `F_SETNOSIGPIPE` flag that every pipe write API applies and verifies before
/// its first byte. The host's SIGPIPE disposition is only ever *read* below.
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

    private func isPending(_ signalNumber: Int32) -> Bool? {
        var pending = sigset_t()
        _ = sigemptyset(&pending)
        guard sigpending(&pending) == 0 else { return nil }
        return sigismember(&pending, signalNumber) == 1
    }

    /// Raw first word of the process-wide SIGPIPE action (the handler pointer).
    /// Only compared for equality, so this makes no assumption about which
    /// value SIG_DFL/SIG_IGN have on this host.
    private func sigPipeActionWord() -> UInt? {
        var action = sigaction()
        guard sigaction(SIGPIPE, nil, &action) == 0 else { return nil }
        return withUnsafeBytes(of: action) { raw in
            raw.loadUnaligned(as: UInt.self)
        }
    }

    private func makePipe() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { throw RelayError.unavailable }
        return fds
    }

    /// A helper that already exited: fixed failure, no SIGPIPE, mask restored,
    /// and the per-descriptor flag was really applied before the failing write.
    func testClosedPeerFailsWithoutSigPipe() throws {
        var fds: [Int32] = [-1, -1]
        guard pipe(&fds) == 0 else { return XCTFail("pipe unavailable") }
        try SocketSupport.makeNonBlocking(fd: fds[1])
        close(fds[0])
        defer { close(fds[1]) }
        XCTAssertEqual(SocketSupport.pipeSigPipeDisabled(fd: fds[1]), false)
        let actionBefore = sigPipeActionWord()
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
        // The failed write left the descriptor flagged ...
        XCTAssertEqual(SocketSupport.pipeSigPipeDisabled(fd: fds[1]), true)
        let after = try XCTUnwrap(currentMask())
        XCTAssertEqual(sigPipeBlocked(before), sigPipeBlocked(after))
        // ... and never changed the process-wide disposition.
        XCTAssertEqual(actionBefore, sigPipeActionWord())
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

    /// `writeAllPipe` itself applies the flag for a standalone caller: the
    /// successful write leaves `F_GETNOSIGPIPE` reporting 1 on that descriptor.
    func testPipeWriteAppliesPerDescriptorNoSigPipe() throws {
        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        XCTAssertEqual(SocketSupport.pipeSigPipeDisabled(fd: fds[1]), false)
        XCTAssertNoThrow(try SocketSupport.disablePipeSigPipe(fd: fds[1]))
        XCTAssertEqual(SocketSupport.pipeSigPipeDisabled(fd: fds[1]), true)

        let fresh = try makePipe()
        defer {
            close(fresh[0])
            close(fresh[1])
        }
        try SocketSupport.writeAllPipe(fd: fresh[1], data: Data([0x46, 0x47]))
        XCTAssertEqual(SocketSupport.pipeSigPipeDisabled(fd: fresh[1]), true)
        var buffer = [UInt8](repeating: 0, count: 2)
        XCTAssertEqual(read(fresh[0], &buffer, buffer.count), 2)
        XCTAssertEqual(buffer, [0x46, 0x47])
    }

    /// A descriptor that cannot carry the flag is refused before any write, and
    /// the refusal is the fixed error - never an unprotected fallback.
    func testUnsupportedDescriptorIsRefusedBeforeWrite() throws {
        XCTAssertThrowsError(try SocketSupport.disablePipeSigPipe(fd: -1)) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
        XCTAssertNil(SocketSupport.pipeSigPipeDisabled(fd: -1))
        XCTAssertThrowsError(
            try SocketSupport.writeAllPipe(fd: -1, data: Data([0x48]))
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }

        let fds = try makePipe()
        close(fds[0])
        close(fds[1])
        XCTAssertThrowsError(try SocketSupport.disablePipeSigPipe(fd: fds[1])) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
    }

    /// A SIGPIPE that was already pending before a *successful* pipe write is
    /// never consumed by this library, and the caller's mask is restored.
    func testPreexistingPendingSigPipeSurvivesSuccessfulPipeWrite() throws {
        var sigpipe = sigset_t()
        _ = sigemptyset(&sigpipe)
        _ = sigaddset(&sigpipe, SIGPIPE)
        var previous = sigset_t()
        _ = sigemptyset(&previous)
        XCTAssertEqual(pthread_sigmask(SIG_BLOCK, &sigpipe, &previous), 0)
        defer { _ = pthread_sigmask(SIG_SETMASK, &previous, nil) }
        XCTAssertEqual(raise(SIGPIPE), 0)
        // Drain only the signal this test injected, while it is still blocked,
        // so nothing leaks into the rest of the suite.
        defer {
            var received: Int32 = 0
            if isPending(SIGPIPE) == true { _ = sigwait(&sigpipe, &received) }
        }
        let blockedBefore = try XCTUnwrap(currentMask())

        let fds = try makePipe()
        defer {
            close(fds[0])
            close(fds[1])
        }
        try SocketSupport.writeAllPipe(fd: fds[1], data: Data([0x49]))
        var buffer = [UInt8](repeating: 0, count: 1)
        XCTAssertEqual(read(fds[0], &buffer, buffer.count), 1)
        XCTAssertEqual(buffer, [0x49])
        XCTAssertEqual(isPending(SIGPIPE), true)
        let blockedAfter = try XCTUnwrap(currentMask())
        XCTAssertTrue(sigPipeBlocked(blockedAfter))
        XCTAssertEqual(sigPipeBlocked(blockedBefore), sigPipeBlocked(blockedAfter))
    }
}
#endif
