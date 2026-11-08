import Foundation
import Darwin

/// App-owned Unix-domain socket listener. The listener exists only in the
/// signed app-group container; each accepted peer is signature- and
/// bundle-verified before a single framed request is read.
final class RelayServer {
    private let identity: ConfiguredIdentity
    private let container: URL
    private let sessions: SessionStore
    private let stateLock = NSLock()
    private let acceptQueue = DispatchQueue(
        label: "org.locklark.browser.safari.relay.accept",
        qos: .userInitiated
    )
    private let maintenanceQueue = DispatchQueue(
        label: "org.locklark.browser.safari.relay.maintenance",
        qos: .utility
    )
    private var listenFD: Int32 = -1
    private var source: DispatchSourceRead?
    private var timer: DispatchSourceTimer?
    private var activeConnections = 0
    private var socketPath: String?
    private var running = false

    var onStatusChange: ((String) -> Void)?

    init(identity: ConfiguredIdentity) throws {
        self.identity = identity
        self.container = try PathPolicy.appGroupContainer(
            appGroupID: identity.appGroupID
        )
        self.sessions = SessionStore(identity: identity)
    }

    func start() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !running else { return }
        let directory = container.appendingPathComponent(
            RelayLimits.relayDirectoryName,
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let socketURL = PathPolicy.relaySocketURL(container: container)
        try PathPolicy.validateRelaySocket(socketURL, container: container)
        try SocketSupport.removeStaleSocket(
            path: socketURL.path,
            container: container
        )
        let fd = try SocketSupport.createListener(path: socketURL.path)
        listenFD = fd
        socketPath = socketURL.path
        let readSource = DispatchSource.makeReadSource(
            fileDescriptor: fd,
            queue: acceptQueue
        )
        readSource.setEventHandler { [weak self] in
            self?.acceptPending()
        }
        readSource.setCancelHandler {
            close(fd)
        }
        readSource.resume()
        source = readSource
        let timer = DispatchSource.makeTimerSource(queue: maintenanceQueue)
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            self?.sessions.sweepExpired()
        }
        timer.resume()
        self.timer = timer
        running = true
        onStatusChange?("Safari relay listening")
    }

    func stop() {
        stateLock.lock()
        guard running else {
            stateLock.unlock()
            return
        }
        running = false
        let source = self.source
        let timer = self.timer
        let path = socketPath
        self.source = nil
        self.timer = nil
        socketPath = nil
        listenFD = -1
        stateLock.unlock()
        source?.cancel()
        timer?.cancel()
        sessions.closeAll()
        if let path {
            _ = unlink(path)
        }
        onStatusChange?("Safari relay stopped")
    }

    private func isRunning() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return running
    }

    private func acceptPending() {
        while isRunning() {
            let client = accept(listenFD, nil, nil)
            if client < 0 { return }
            stateLock.lock()
            let allowed = activeConnections < RelayLimits.maxConnections
            if allowed { activeConnections += 1 }
            stateLock.unlock()
            guard allowed else {
                close(client)
                continue
            }
            // A write to a peer that already went away must never raise
            // SIGPIPE. Refuse the connection if the socket option fails.
            guard (try? SocketSupport.disableSigPipe(fd: client)) != nil else {
                close(client)
                stateLock.lock()
                activeConnections = max(0, activeConnections - 1)
                stateLock.unlock()
                continue
            }
            Thread.detachNewThread { [weak self] in
                self?.serve(client: client)
            }
        }
    }

    private func serve(client: Int32) {
        defer {
            close(client)
            stateLock.lock()
            activeConnections = max(0, activeConnections - 1)
            stateLock.unlock()
        }
        SocketSupport.applyTimeouts(
            fd: client,
            seconds: RelayLimits.socketTimeout
        )
        guard PeerVerifier.accepts(fd: client, identity: identity) else {
            return
        }
        while isRunning() {
            do {
                let raw = try SocketSupport.readFrame(fd: client)
                // Trusted hop: the peer was SecCode/Team/bundle/UID verified
                // above, so this parser (and only this) accepts the
                // native-context profile on every operation.
                guard let request = RelayRequest.parseNative(raw) else {
                    try? SocketSupport.writeFrame(
                        fd: client,
                        object: RelayReply.protocolFailure()
                    )
                    return
                }
                let reply = sessions.handle(request)
                try SocketSupport.writeFrame(fd: client, object: reply)
                if request.operation == .close { return }
            } catch {
                return
            }
        }
    }
}
