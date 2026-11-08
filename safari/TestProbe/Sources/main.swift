#if canImport(Darwin)
import Darwin
import Foundation
import LocklarkSafariShared

/// Standalone macOS probe for the relay's SIGPIPE policy.
///
/// This runs as its own process (never inside the XCTest host) and sets the
/// process-wide SIGPIPE disposition to SIG_DFL, so a missing guard really does
/// terminate the process. It proves that:
///
/// - a write to a socket whose peer closed, and a write to a pipe whose read
///   end closed, both return the fixed `RelayError.unavailable` and the process
///   survives under the default SIGPIPE action;
/// - the caller's exact thread signal mask is restored on success and failure;
/// - a SIGPIPE that was already pending before the write is not consumed.
///
/// Exit status 0 means every check passed. This is a macOS-only, native
/// executable; it is not a claim that the Linux worker ran it.

var failures: [String] = []

func check(_ condition: Bool, _ name: String) {
    if condition {
        print("ok   \(name)")
    } else {
        failures.append(name)
        print("FAIL \(name)")
    }
}

func writeFailsUnavailable(_ body: () throws -> Void) -> Bool {
    do {
        try body()
        return false
    } catch RelayError.unavailable {
        return true
    } catch {
        return false
    }
}

func sigPipeSet() -> sigset_t {
    var set = sigset_t()
    _ = sigemptyset(&set)
    _ = sigaddset(&set, SIGPIPE)
    return set
}

func currentMask() -> sigset_t? {
    var mask = sigset_t()
    _ = sigemptyset(&mask)
    guard pthread_sigmask(SIG_BLOCK, nil, &mask) == 0 else { return nil }
    return mask
}

let comparedSignals: [Int32] = [
    SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, SIGALRM, SIGCHLD,
]

func sameMask(_ lhs: sigset_t, _ rhs: sigset_t) -> Bool {
    for signalNumber in comparedSignals {
        var left = lhs
        var right = rhs
        if sigismember(&left, signalNumber) != sigismember(&right, signalNumber) {
            return false
        }
    }
    return true
}

func isBlocked(_ signalNumber: Int32, in mask: sigset_t) -> Bool {
    var copy = mask
    return sigismember(&copy, signalNumber) == 1
}

func isPending(_ signalNumber: Int32) -> Bool? {
    var pending = sigset_t()
    _ = sigemptyset(&pending)
    guard sigpending(&pending) == 0 else { return nil }
    return sigismember(&pending, signalNumber) == 1
}

// 1. Default SIGPIPE action in this standalone process.
check(signal(SIGPIPE, SIG_DFL) != SIG_ERR, "SIGPIPE disposition is SIG_DFL")

// 2. Socket with SO_NOSIGPIPE, peer already closed.
do {
    var pair: [Int32] = [-1, -1]
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, "socketpair created")
    check(
        (try? SocketSupport.disableSigPipe(fd: pair[1])) != nil,
        "SO_NOSIGPIPE set on send socket"
    )
    close(pair[0])
    check(
        writeFailsUnavailable {
            try SocketSupport.writeAll(
                fd: pair[1],
                data: Data(repeating: 0x41, count: 32)
            )
        },
        "closed-peer socket write -> RelayError.unavailable"
    )
    close(pair[1])
}

// 3. Socket without SO_NOSIGPIPE: the thread guard alone must still protect.
do {
    var pair: [Int32] = [-1, -1]
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, "unprotected socketpair")
    close(pair[0])
    check(
        writeFailsUnavailable {
            try SocketSupport.writeAll(
                fd: pair[1],
                data: Data(repeating: 0x42, count: 32)
            )
        },
        "thread guard covers socket write without SO_NOSIGPIPE"
    )
    let mask = currentMask()
    check(
        mask.map { !isBlocked(SIGPIPE, in: $0) } == true,
        "thread mask restored after unprotected socket write"
    )
    close(pair[1])
}

// 4. Pipe with the read end closed (helper stdin case).
do {
    var fds: [Int32] = [-1, -1]
    check(pipe(&fds) == 0, "pipe created")
    let before = currentMask()
    close(fds[0])
    check(
        writeFailsUnavailable {
            try SocketSupport.writeAllPipe(
                fd: fds[1],
                data: Data(repeating: 0x43, count: 32)
            )
        },
        "closed-pipe write -> RelayError.unavailable"
    )
    close(fds[1])
    let after = currentMask()
    if let before, let after {
        check(sameMask(before, after), "thread mask restored after failed pipe write")
    } else {
        check(false, "thread mask readable around failed pipe write")
    }
}

// 5. A caller that already blocks SIGPIPE keeps it blocked afterwards.
do {
    var fds: [Int32] = [-1, -1]
    check(pipe(&fds) == 0, "pipe created for blocked-mask case")
    var sigpipe = sigPipeSet()
    var previous = sigset_t()
    _ = sigemptyset(&previous)
    check(
        pthread_sigmask(SIG_BLOCK, &sigpipe, &previous) == 0,
        "caller blocks SIGPIPE"
    )
    let before = currentMask()
    var openWriteSucceeded = true
    do {
        try SocketSupport.writeAllPipe(
            fd: fds[1],
            data: Data(repeating: 0x44, count: 32)
        )
    } catch {
        openWriteSucceeded = false
    }
    check(openWriteSucceeded, "open pipe write succeeds")
    let after = currentMask()
    if let before, let after {
        check(sameMask(before, after), "blocked caller mask preserved")
        check(isBlocked(SIGPIPE, in: after), "SIGPIPE still blocked for caller")
    } else {
        check(false, "thread mask readable around blocked-mask write")
    }
    _ = pthread_sigmask(SIG_SETMASK, &previous, nil)
    close(fds[0])
    close(fds[1])
}

// 6. A pre-existing pending SIGPIPE is never consumed by a successful write.
do {
    var sigpipe = sigPipeSet()
    var previous = sigset_t()
    _ = sigemptyset(&previous)
    check(
        pthread_sigmask(SIG_BLOCK, &sigpipe, &previous) == 0,
        "block SIGPIPE for pending-signal case"
    )
    check(raise(SIGPIPE) == 0, "raise a pre-existing pending SIGPIPE")
    var fds: [Int32] = [-1, -1]
    check(pipe(&fds) == 0, "pipe created for pending-signal case")
    do {
        try SocketSupport.writeAllPipe(
            fd: fds[1],
            data: Data(repeating: 0x45, count: 8)
        )
        check(true, "write with a pre-existing pending SIGPIPE succeeds")
    } catch {
        check(false, "write with a pre-existing pending SIGPIPE succeeds")
    }
    check(
        isPending(SIGPIPE) == true,
        "pre-existing pending SIGPIPE left untouched"
    )
    close(fds[0])
    close(fds[1])
    // Drain only our own injected signal, still blocked, then restore.
    var received: Int32 = 0
    _ = sigwait(&sigpipe, &received)
    _ = pthread_sigmask(SIG_SETMASK, &previous, nil)
}

// 7. A pre-existing pending SIGPIPE survives a *failing* write too: only the
//    signal raised by our own write may be consumed.
do {
    var sigpipe = sigPipeSet()
    var previous = sigset_t()
    _ = sigemptyset(&previous)
    check(
        pthread_sigmask(SIG_BLOCK, &sigpipe, &previous) == 0,
        "block SIGPIPE for failing-pending case"
    )
    check(raise(SIGPIPE) == 0, "raise a pre-existing pending SIGPIPE (failing write)")
    var fds: [Int32] = [-1, -1]
    check(pipe(&fds) == 0, "pipe created for failing-pending case")
    close(fds[0])
    check(
        writeFailsUnavailable {
            try SocketSupport.writeAllPipe(
                fd: fds[1],
                data: Data(repeating: 0x46, count: 32)
            )
        },
        "failing write with pre-existing pending SIGPIPE -> unavailable"
    )
    close(fds[1])
    check(
        isPending(SIGPIPE) == true,
        "pre-existing pending SIGPIPE not consumed by failing write"
    )
    var received: Int32 = 0
    _ = sigwait(&sigpipe, &received)
    _ = pthread_sigmask(SIG_SETMASK, &previous, nil)
}

// 8. The process is still alive after every closed-peer write above.
check(true, "probe process survived all closed-peer writes")

if failures.isEmpty {
    print("PASS safari SIGPIPE probe (\(#file))")
    exit(0)
} else {
    print("FAILED \(failures.count) safari SIGPIPE probe check(s)")
    exit(1)
}
#else
import Foundation
// Non-Darwin hosts cannot exercise socket/pipe SIGPIPE semantics; fail closed
// instead of reporting a pass that did not happen.
FileHandle.standardError.write(Data("skip: Safari SIGPIPE probe requires macOS\n".utf8))
exit(2)
#endif
