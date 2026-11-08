import Foundation

/// The containing app is the only component allowed to launch the helper. The
/// executable location and argv are compile-time constants: no JavaScript,
/// envelope field, environment file or socket frame can choose them.
enum HelperLauncher {
    static let fixedArguments = ["--safari-browser"]

    static func helperURL(bundle: Bundle = .main) throws -> URL {
        guard let executable = bundle.executableURL else {
            throw RelayError.unavailable
        }
        let directory = executable.deletingLastPathComponent()
        let url = directory.appendingPathComponent(
            RelayLimits.helperName,
            isDirectory: false
        )
        guard PathPolicy.isContained(url, in: directory) else {
            throw RelayError.unavailable
        }
        let values = try? url.resourceValues(
            forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
        )
        guard values?.isRegularFile == true,
              values?.isSymbolicLink != true
        else { throw RelayError.unavailable }
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            throw RelayError.unavailable
        }
        return url
    }

    static func start() throws -> Process {
        let process = Process()
        process.executableURL = try helperURL()
        process.arguments = fixedArguments
        // The child gets only a fixed baseline: no ambient tokens, no DYLD_*
        // injection, no proxy settings and no LOCKLARK_* overrides. HOME is
        // the current user's home directory so the Go helper locates the
        // existing Locklark runtime and config, never a different user's.
        process.environment = HelperEnvironment.minimal(
            home: FileManager.default.homeDirectoryForCurrentUser.path,
            temporaryDirectory: FileManager.default.temporaryDirectory.path
        )
        return process
    }
}

/// One opaque connection token maps to exactly one embedded helper process.
/// The helper survives polling; it is closed on session close, TTL expiry or
/// any helper/protocol failure. Host frames are bounded and are never replayed
/// or synthesized.
final class HelperSession {
    private let profileKey: String?
    private let process: Process
    private let stdinPipe: Pipe
    private let stdoutPipe: Pipe
    private let lock = NSLock()
    /// Sole owner of the stdin descriptor: all access, the bounded write and
    /// the pipe/process teardown are serialized by this gate.
    private let stdinGate: SerializedPipeWriter
    private var decoder = FrameDecoder()
    private var pending: [[String: Any]] = []
    private var pendingBytes = 0
    private var closed = false
    private var unavailable = false
    private(set) var createdAt = Date()

    init(identity: ConfiguredIdentity, profileKey: String?) throws {
        self.profileKey = profileKey
        _ = identity
        let process = try HelperLauncher.start()
        self.process = process
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        self.stdinPipe = stdinPipe
        self.stdoutPipe = stdoutPipe
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = FileHandle.nullDevice
        // stdin is non-blocking from the first use: the bounded write below
        // relies on EAGAIN plus `poll` instead of a blocking pipe write that
        // could pin the app behind a helper that never reads.
        do {
            try SocketSupport.makeNonBlocking(
                fd: stdinPipe.fileHandleForWriting.fileDescriptor
            )
            try process.run()
        } catch {
            try? stdinPipe.fileHandleForWriting.close()
            try? stdoutPipe.fileHandleForReading.close()
            throw RelayError.unavailable
        }
        self.stdinGate = SerializedPipeWriter(
            fd: stdinPipe.fileHandleForWriting.fileDescriptor,
            write: { fd, data, deadline, isCancelled in
                try SocketSupport.writeAllPipeBounded(
                    fd: fd,
                    data: data,
                    deadline: deadline,
                    isCancelled: isCancelled
                )
            },
            teardown: {
                // Runs on the gate queue only, so it can never close the pipes
                // or terminate the process underneath an in-flight write.
                HelperSession.tearDown(
                    process: process,
                    stdinPipe: stdinPipe,
                    stdoutPipe: stdoutPipe
                )
            }
        )
        stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty {
                self?.markUnavailable()
                return
            }
            self?.consume(data)
        }
        process.terminationHandler = { [weak self] _ in
            self?.markUnavailable()
        }
    }

    var profile: String? { profileKey }
    var isUsable: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !closed && !unavailable
    }

    func write(_ frame: [String: Any]) throws {
        // Encoding happens before any lock is taken: a throwing encoder must
        // never leave session state locked, and it has no side effect on the
        // gate, so the next write or close still works.
        let encoded = try FrameCodec.encodeJSONObject(frame)
        lock.lock()
        let usable = !closed && !unavailable
        lock.unlock()
        guard usable else { throw RelayError.unavailable }
        do {
            // Helper stdin is a pipe, so SO_NOSIGPIPE does not apply: the
            // thread-local SIGPIPE guard in the bounded write turns a helper
            // that already exited into a fixed RelayError.unavailable instead
            // of terminating the app. The gate re-checks revocation inside its
            // queued operation and the bounded write observes it through its
            // cancellation callback, so close can never pull stdin out from
            // under this write. A partial frame is never retried.
            try stdinGate.write(encoded)
        } catch {
            // Unknown number of bytes may have reached the helper: drop the
            // session instead of replaying the frame.
            markUnavailable()
            throw RelayError.unavailable
        }
    }

    func replyFrames(token: String) -> [String: Any] {
        lock.lock()
        if closed || unavailable {
            lock.unlock()
            return RelayReply.failure(token: token)
        }
        var frames: [[String: Any]] = []
        var bytes = 0
        while !pending.isEmpty, frames.count < RelayLimits.maxFramesPerPoll {
            let next = pending[0]
            let size = RelayEnvelope.serializedSize(next)
            guard bytes + size <= RelayLimits.maxReplyBytes - 512 else {
                break
            }
            pending.removeFirst()
            pendingBytes -= size
            frames.append(next)
            bytes += size
        }
        lock.unlock()
        return RelayReply.success(token: token, frames: frames)
    }

    private func consume(_ data: Data) {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        var decoded: [Data]
        do {
            decoded = try decoder.append(data)
        } catch {
            unavailable = true
            lock.unlock()
            stdinGate.close()
            return
        }
        for frameData in decoded {
            guard let object = try? JSONSerialization.jsonObject(with: frameData),
                  let frame = RelayEnvelope.object(object),
                  RelayEnvelope.isValidFrame(frame)
            else {
                unavailable = true
                break
            }
            let size = RelayEnvelope.serializedSize(frame)
            guard pending.count < RelayLimits.maxQueuedFrames,
                  pendingBytes + size <= RelayLimits.maxQueuedBytes
            else {
                unavailable = true
                break
            }
            pending.append(frame)
            pendingBytes += size
        }
        let failed = unavailable
        lock.unlock()
        if failed { stdinGate.close() }
    }

    private func markUnavailable() {
        // Revoke first (short gate state lock, never the write queue) so a
        // queued write refuses and an in-flight bounded write aborts on its
        // next poll slice.
        stdinGate.revoke()
        lock.lock()
        unavailable = true
        lock.unlock()
    }

    func close() {
        // Refuse queued writes before touching session state: `revoke` only
        // takes the gate's short state lock and never waits for the queue.
        stdinGate.revoke()
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        pending.removeAll()
        pendingBytes = 0
        lock.unlock()
        // No session lock is held here. The gate waits at most its bounded
        // deadline for a current write and then tears down exactly once, on
        // its own queue, before the pipes or process can be closed.
        stdinGate.close()
    }

    /// Single teardown body. Only the gate queue calls this.
    private static func tearDown(
        process: Process,
        stdinPipe: Pipe,
        stdoutPipe: Pipe
    ) {
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        process.terminationHandler = nil
        if process.isRunning {
            process.terminate()
        }
        try? stdinPipe.fileHandleForWriting.close()
        try? stdoutPipe.fileHandleForReading.close()
    }
}
