import Foundation
import Darwin

/// App-owned Unix-domain socket listener. The listener exists only in the
/// signed app-group container; each accepted peer is signature- and
/// bundle-verified before a single framed request is read.
///
/// Lifecycle: every `start()` installs a brand-new `SessionStore` under a new
/// epoch through `stores`, and every accepted connection captures that
/// store/epoch once. A connection accepted before a stop/start cycle is served
/// by - and only by - the captured (already closed) store; it can never bind a
/// helper against the store of a later generation.
final class RelayServer {
    private let identity: ConfiguredIdentity
    private let container: URL
    private let stores: StoreEpochTable<SessionStore>
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
        // Never used before the first successful start; it only establishes the
        // epoch table. Each start installs a fresh store.
        self.stores = StoreEpochTable(SessionStore(identity: identity))
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

        // A new generation for every start: the previous store (if any) is
        // already closed, and no lease captured against it can become current
        // again.
        let store = SessionStore(identity: identity)
        _ = stores.replace(with: store)

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

        let maintenance = DispatchSource.makeTimerSource(queue: maintenanceQueue)
        maintenance.schedule(deadline: .now() + 60, repeating: 60)
        // Bound to the store of *this* generation, never to a later one.
        maintenance.setEventHandler {
            store.sweepExpired()
        }
        maintenance.resume()
        timer = maintenance
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
        // Unlink under the lock so a concurrent start cannot rebind this path
        // only to have it removed here.
        if let path {
            _ = unlink(path)
        }
        let lease = stores.capture()
        stateLock.unlock()
        source?.cancel()
        timer?.cancel()
        // Revokes every pending reservation and ready session and closes the
        // store permanently: a worker accepted before this stop can never open
        // a helper afterwards.
        lease.store.closeAll()
        onStatusChange?("Safari relay stopped")
    }

    private func acceptPending() {
        while true {
            // Snapshot the listener *and* its store generation under one
            // lock, before accept: the connection accepted next belongs to
            // this listener generation, never to a store installed later.
            stateLock.lock()
            let listenerRunning = running
            let listenerFD = listenFD
            let lease = stores.capture()
            stateLock.unlock()
            guard listenerRunning, listenerFD >= 0 else { return }
            let client = accept(listenerFD, nil, nil)
            if client < 0 { return }
            stateLock.lock()
            let stillRunning = running &&
                listenFD == listenerFD &&
                stores.isCurrent(lease.epoch)
            let allowed = stillRunning &&
                activeConnections < RelayLimits.maxConnections
            if allowed { activeConnections += 1 }
            stateLock.unlock()
            guard stillRunning else {
                close(client)
                return
            }
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
            // Serve with the lease captured before accept, so this peer is
            // bound to the listener generation it actually connected to.
            Thread.detachNewThread { [weak self] in
                self?.serve(client: client, lease: lease)
            }
        }
    }

    private func serve(
        client: Int32,
        lease: StoreEpochTable<SessionStore>.Lease
    ) {
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
        while stores.isCurrent(lease.epoch) {
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
                let reply = lease.store.handle(request)
                try SocketSupport.writeFrame(fd: client, object: reply)
                if request.operation == .close { return }
            } catch {
                return
            }
        }
    }
}
