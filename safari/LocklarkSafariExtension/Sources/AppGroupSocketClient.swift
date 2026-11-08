#if canImport(Darwin)
import Foundation
import Darwin

/// Blocking, serialized, one-request/one-reply client from the Safari web
/// extension handler to the containing app. It connects only to the fixed
/// app-group socket path and never accepts a path or fd from Safari messages.
final class AppGroupSocketClient {
    private let fd: Int32
    private let lock = NSLock()
    private var closed = false

    init(socketURL: URL) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RelayError.unavailable }
        // A containing app that quits mid-request must never SIGPIPE-kill the
        // extension handler process. Refuse the socket if the option fails.
        do {
            try SocketSupport.disableSigPipe(fd: fd)
        } catch {
            close(fd)
            throw RelayError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketURL.path.utf8)
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
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            close(fd)
            throw RelayError.unavailable
        }
        SocketSupport.applyTimeouts(fd: fd, seconds: RelayLimits.socketTimeout)
        self.fd = fd
    }

    deinit {
        close()
    }

    func request(_ object: [String: Any]) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { throw RelayError.closed }
        try SocketSupport.writeFrame(fd: fd, object: object)
        return try SocketSupport.readFrame(fd: fd)
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        Darwin.close(fd)
    }
}
#endif
