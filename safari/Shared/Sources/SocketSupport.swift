#if canImport(Darwin)
import Foundation
import Darwin

/// Fixed, payload-free I/O helpers for the Safari relay.
///
/// SIGPIPE policy: this process never changes the process-wide disposition of
/// SIGPIPE. Sockets get the `SO_NOSIGPIPE` socket option when they are
/// created/accepted (checked; failure is a fixed `unavailable`). Pipes - which
/// have no `SO_NOSIGPIPE` - get the per-descriptor `F_SETNOSIGPIPE` flag on
/// entry to every pipe write API, read back with `F_GETNOSIGPIPE`; a host that
/// does not support the flag, or drops it, is refused with the same fixed
/// `unavailable` *before* the first byte is written and is never left to
/// unprotected I/O. The thread-scoped guard is retained as defence in depth for
/// every write: it blocks SIGPIPE only for the calling thread, restores the
/// caller's exact original pthread signal mask on every exit path, never
/// consumes a SIGPIPE that was already pending before the write, and consumes
/// only the thread-directed SIGPIPE the failed write itself raised (via
/// `sigpending` + `sigwait`) while it is still blocked. A closed peer therefore
/// turns into a fixed `RelayError.unavailable` instead of terminating the app or
/// extension - including inside the multithreaded XCTest host, where a
/// thread-scoped mask alone cannot protect a write issued from another thread.
public enum SocketSupport {
    /// Applies `SO_NOSIGPIPE` to a socket. Failure is refused, never ignored.
    public static func disableSigPipe(fd: Int32) throws {
        var enabled: Int32 = 1
        let size = socklen_t(MemoryLayout<Int32>.size)
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, size) == 0 else {
            throw RelayError.unavailable
        }
    }

    /// Applies the per-descriptor `F_SETNOSIGPIPE` flag to a pipe and reads it
    /// back. Darwin pipes have no `SO_NOSIGPIPE` socket option, so this
    /// descriptor flag is the only kernel-level SIGPIPE opt-out for a pipe
    /// write: with it set, a write to a pipe whose read end has closed fails
    /// with `EPIPE` instead of raising a process-wide SIGPIPE.
    ///
    /// A descriptor that cannot take the flag (a non-pipe/non-socket fd, an
    /// invalid fd) or one that does not report it back is a fixed
    /// `RelayError.unavailable`. The failure is returned to the caller before
    /// any byte is written; there is no unprotected fallback.
    public static func disablePipeSigPipe(fd: Int32) throws {
        guard fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else {
            throw RelayError.unavailable
        }
        guard fcntl(fd, F_GETNOSIGPIPE, 0) == 1 else {
            throw RelayError.unavailable
        }
    }

    /// Reads back the per-descriptor `F_SETNOSIGPIPE` flag. Nil means the flag
    /// could not be read at all (an fd that cannot carry it); `false` means the
    /// descriptor would currently write without it.
    public static func pipeSigPipeDisabled(fd: Int32) -> Bool? {
        let enabled = fcntl(fd, F_GETNOSIGPIPE, 0)
        if enabled < 0 { return nil }
        return enabled == 1
    }

    static func applyTimeouts(fd: Int32, seconds: TimeInterval) {
        var timeout = timeval(
            tv_sec: Int(seconds),
            tv_usec: 0
        )
        let size = socklen_t(MemoryLayout<timeval>.size)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, size)
        }
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, size)
        }
    }

    /// Socket write. The caller must have applied `disableSigPipe(fd:)` when
    /// the socket was created/accepted; the thread guard below is defence in
    /// depth so a missed `SO_NOSIGPIPE` still cannot kill the process.
    public static func writeAll(fd: Int32, data: Data) throws {
        try writeAllGuarded(fd: fd, data: data, deadline: nil, isCancelled: { false })
    }

    /// Pipe write (the helper's stdin).
    ///
    /// The per-descriptor `F_SETNOSIGPIPE` flag is applied and verified before
    /// the first byte; if this host cannot apply it the write fails with the
    /// fixed `RelayError.unavailable` and never falls back to unprotected pipe
    /// I/O. The thread-local guard in `writeAllGuarded` remains as defence in
    /// depth, and a helper that already exited turns the write into a fixed
    /// `RelayError.unavailable`.
    public static func writeAllPipe(fd: Int32, data: Data) throws {
        try disablePipeSigPipe(fd: fd)
        try writeAllGuarded(fd: fd, data: data, deadline: nil, isCancelled: { false })
    }

    /// Switches a descriptor to non-blocking exactly once, before first use.
    /// `writeAllPipeBounded` refuses to rely on a blocking pipe write.
    public static func makeNonBlocking(fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw RelayError.unavailable
        }
    }

    /// Bounded pipe write for the helper's stdin.
    ///
    /// `fd` must already be non-blocking (`makeNonBlocking`). Bytes are written
    /// until the absolute monotonic `deadline`; a descriptor that cannot take
    /// the remaining bytes in that window - because the helper is not reading,
    /// or because `isCancelled` reports a revoked session - fails with the
    /// fixed `RelayError.unavailable`. A partially written frame is never
    /// retried here: the caller drops the session instead of replaying.
    public static func writeAllPipeBounded(
        fd: Int32,
        data: Data,
        deadline: DispatchTime,
        isCancelled: () -> Bool
    ) throws {
        // The descriptor-level SIGPIPE opt-out comes first: a descriptor that
        // cannot carry it is refused here, before any byte is written and
        // before the deadline loop below could ever issue one.
        try disablePipeSigPipe(fd: fd)
        // Contract check: a blocking descriptor would ignore the deadline and
        // could stall the caller for as long as the peer does not read.
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0, (flags & O_NONBLOCK) != 0 else {
            throw RelayError.unavailable
        }
        try writeAllGuarded(
            fd: fd,
            data: data,
            deadline: deadline,
            isCancelled: isCancelled
        )
    }

    /// Core write loop. Any write failure - `EPIPE`, `ECONNRESET`, a zero
    /// length write or an unexpected errno - maps to the single fixed
    /// `RelayError.unavailable`; no errno text, peer data or frame content is
    /// ever surfaced or logged. A partially written frame is never retried:
    /// the caller must drop the session instead. With a `deadline` an
    /// `EAGAIN` from a non-blocking descriptor waits for writability in short
    /// poll slices, re-checking deadline and cancellation each slice.
    private static func writeAllGuarded(
        fd: Int32,
        data: Data,
        deadline: DispatchTime?,
        isCancelled: () -> Bool
    ) throws {
        var sigpipe = sigset_t()
        _ = sigemptyset(&sigpipe)
        _ = sigaddset(&sigpipe, SIGPIPE)

        var originalMask = sigset_t()
        _ = sigemptyset(&originalMask)
        guard pthread_sigmask(SIG_BLOCK, &sigpipe, &originalMask) == 0 else {
            throw RelayError.unavailable
        }
        defer {
            // Always restore the caller's exact thread signal mask, including
            // on every throw path below.
            _ = pthread_sigmask(SIG_SETMASK, &originalMask, nil)
        }

        // A SIGPIPE that is already pending belongs to an earlier operation;
        // it is left untouched and never consumed here.
        guard let preexistingPending = isSigPipePending() else {
            throw RelayError.unavailable
        }

        var failed = false
        var raisedSigPipe = false
        var offset = 0
        while offset < data.count {
            if let deadline {
                // Absolute monotonic check before every attempt - first byte,
                // EINTR retry and post-poll retry alike - so a revoked or
                // expired write never issues even one further byte.
                if isCancelled() || DispatchTime.now() >= deadline {
                    failed = true
                    break
                }
            }
            let written = data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.write(
                    fd,
                    base.advanced(by: offset),
                    data.count - offset
                )
            }
            if written < 0 {
                if errno == EINTR { continue }
                if let deadline, errno == EAGAIN || errno == EWOULDBLOCK {
                    if waitWritable(fd: fd, deadline: deadline, isCancelled: isCancelled) {
                        continue
                    }
                    // Deadline expired or the session was revoked: fail closed
                    // without retrying the partial frame. No write failed, so
                    // this path raises no SIGPIPE.
                    failed = true
                    break
                }
                failed = true
                raisedSigPipe = true
                break
            }
            if written == 0 {
                failed = true
                raisedSigPipe = true
                break
            }
            offset += written
        }

        if raisedSigPipe, !preexistingPending {
            // Consume only the thread-directed SIGPIPE this write raised while
            // it is still blocked, before the mask is restored.
            consumeNewPendingSigPipe(sigpipe: &sigpipe)
        }
        if failed { throw RelayError.unavailable }
    }

    /// One poll slice of a bounded pipe write: short enough that a stalled
    /// helper or a revocation is observed promptly, never unboundedly.
    static let pollIntervalMilliseconds = 20

    /// Waits for writability of a non-blocking descriptor. `false` means the
    /// caller must fail closed: the deadline expired, the pipe hung up or
    /// errored, or the cancellation callback reported a revoked session.
    private static func waitWritable(
        fd: Int32,
        deadline: DispatchTime,
        isCancelled: () -> Bool
    ) -> Bool {
        while true {
            if isCancelled() { return false }
            let now = DispatchTime.now()
            if now.uptimeNanoseconds >= deadline.uptimeNanoseconds { return false }
            let remaining = deadline.uptimeNanoseconds - now.uptimeNanoseconds
            let slice = min(
                remaining,
                UInt64(pollIntervalMilliseconds) * 1_000_000
            )
            let milliseconds = Int32(min(slice / 1_000_000 + 1, UInt64(Int32.max)))
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&descriptor, 1, milliseconds)
            if ready < 0 {
                if errno == EINTR { continue }
                return false
            }
            if ready == 0 { continue }
            if descriptor.revents & Int16(POLLOUT) != 0 { return true }
            return false
        }
    }

    /// Nil means the pending set could not be read, which fails closed.
    private static func isSigPipePending() -> Bool? {
        var pending = sigset_t()
        _ = sigemptyset(&pending)
        guard sigpending(&pending) == 0 else { return nil }
        return sigismember(&pending, SIGPIPE) == 1
    }

    private static func consumeNewPendingSigPipe(sigpipe: inout sigset_t) {
        guard isSigPipePending() == true else { return }
        var received: Int32 = 0
        _ = sigwait(&sigpipe, &received)
    }

    static func readExactly(fd: Int32, count: Int) throws -> Data {
        guard count >= 0, count <= RelayLimits.maxFrameBytes else {
            throw RelayError.invalidFrame
        }
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            var chunk = [UInt8](repeating: 0, count: count - result.count)
            let readCount = chunk.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base, raw.count)
            }
            if readCount < 0 {
                if errno == EINTR { continue }
                throw RelayError.unavailable
            }
            if readCount == 0 { throw RelayError.closed }
            result.append(contentsOf: chunk.prefix(readCount))
        }
        return result
    }

    static func readFrame(fd: Int32) throws -> [String: Any] {
        let header = try readExactly(fd: fd, count: 4)
        let length = header.withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self)
        }.littleEndian
        guard length <= RelayLimits.maxFrameBytes else {
            throw RelayError.invalidFrame
        }
        let payload = try readExactly(fd: fd, count: Int(length))
        guard let object = try? JSONSerialization.jsonObject(with: payload),
              let dictionary = RelayEnvelope.object(object),
              RelayEnvelope.isValidFrame(dictionary)
        else { throw RelayError.invalidFrame }
        return dictionary
    }

    static func writeFrame(fd: Int32, object: [String: Any]) throws {
        let data = try FrameCodec.encodeJSONObject(object)
        try writeAll(fd: fd, data: data)
    }

    /// Expected byte image of a Darwin `audit_token_t`: eight host-order
    /// 32-bit words (auid, euid, egid, ruid, rgid, pid, asid, pidversion).
    public static let auditTokenLength = 8 * MemoryLayout<UInt32>.size

    /// Kernel-supplied identity of the connected peer.
    ///
    /// `token` is the opaque `audit_token_t` image returned by
    /// `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`. It is the only handle used to
    /// look the peer up in SecCode (`kSecGuestAttributeAudit`), so it pins the
    /// exact process instance and pidversion: a numeric PID would be
    /// re-resolvable to a different process between check and use. `pid`,
    /// `uid` and `pidVersion` are metadata decoded from the same token; they
    /// are never used as a lookup key. The token bytes are never logged.
    public struct PeerAuditToken {
        public let token: Data
        public let pid: Int32
        public let uid: UInt32
        public let pidVersion: UInt32
    }

    /// Fetches the peer audit token plus metadata. Every failure - no peer
    /// credentials, an unsupported `LOCAL_PEERTOKEN`, a short or oversized
    /// token, an implausible pid or an euid that disagrees with `getpeereid` -
    /// returns nil so the caller fails closed.
    public static func peerAuditToken(fd: Int32) -> PeerAuditToken? {
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        guard getpeereid(fd, &peerUID, &peerGID) == 0 else { return nil }
        let wordCount = auditTokenLength / MemoryLayout<UInt32>.size
        var words = [UInt32](repeating: 0, count: wordCount)
        var length = socklen_t(auditTokenLength)
        let result = words.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, base, &length)
        }
        guard result == 0 else { return nil }
        // Exact expected byte count only: a truncated or oversized token is
        // refused instead of being partially trusted.
        guard Int(length) == auditTokenLength, words.count == wordCount else {
            return nil
        }
        let tokenUID = words[1]
        let tokenPID = Int32(bitPattern: words[5])
        let pidVersion = words[7]
        guard tokenPID > 0, tokenUID == UInt32(peerUID) else { return nil }
        var token = Data()
        words.withUnsafeBytes { raw in
            if let base = raw.baseAddress {
                token = Data(bytes: base, count: auditTokenLength)
            }
        }
        guard token.count == auditTokenLength else { return nil }
        return PeerAuditToken(
            token: token,
            pid: tokenPID,
            uid: tokenUID,
            pidVersion: pidVersion
        )
    }

    static func createListener(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RelayError.unavailable }
        do {
            try disableSigPipe(fd: fd)
        } catch {
            close(fd)
            throw RelayError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count + 1 <= capacity else {
            close(fd)
            throw RelayError.invalidConfiguration
        }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
            raw[pathBytes.count] = 0
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            close(fd)
            throw RelayError.unavailable
        }
        guard chmod(path, 0o600) == 0 else {
            close(fd)
            _ = unlink(path)
            throw RelayError.unavailable
        }
        guard listen(fd, Int32(RelayLimits.maxConnections)) == 0 else {
            close(fd)
            _ = unlink(path)
            throw RelayError.unavailable
        }
        return fd
    }

    static func removeStaleSocket(path: String, container: URL) throws {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            if errno == ENOENT { return }
            throw RelayError.unavailable
        }
        guard (info.st_mode & S_IFMT) == S_IFSOCK,
              info.st_uid == getuid(),
              PathPolicy.isContained(URL(fileURLWithPath: path), in: container)
        else { throw RelayError.invalidConfiguration }
        guard unlink(path) == 0 else { throw RelayError.unavailable }
    }
}

#endif
