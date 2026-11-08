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
        process.environment = nil
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
    private let writeQueue = DispatchQueue(label: "org.locklark.browser.safari.helper.write")
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
        do {
            try process.run()
        } catch {
            throw RelayError.unavailable
        }
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
        lock.lock()
        if closed || unavailable {
            lock.unlock()
            throw RelayError.unavailable
        }
        let encoded = try FrameCodec.encodeJSONObject(frame)
        lock.unlock()
        try writeQueue.sync {
            // Helper stdin is a pipe, so SO_NOSIGPIPE does not apply: the
            // thread-local SIGPIPE guard in writeAllPipe turns a helper that
            // already exited into a fixed RelayError.unavailable instead of
            // terminating the app. A partial frame is never retried.
            try SocketSupport.writeAllPipe(
                fd: stdinPipe.fileHandleForWriting.fileDescriptor,
                data: encoded
            )
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
            closeProcess()
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
        if failed { closeProcess() }
    }

    private func markUnavailable() {
        lock.lock()
        unavailable = true
        lock.unlock()
    }

    func close() {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        pending.removeAll()
        pendingBytes = 0
        lock.unlock()
        closeProcess()
    }

    private func closeProcess() {
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        process.terminationHandler = nil
        if process.isRunning {
            process.terminate()
        }
        try? stdinPipe.fileHandleForWriting.close()
        try? stdoutPipe.fileHandleForReading.close()
    }
}
