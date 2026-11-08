#if canImport(Darwin)
import Foundation
import Darwin

enum SocketSupport {
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

    static func writeAll(fd: Int32, data: Data) throws {
        var offset = 0
        while offset < data.count {
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
                throw RelayError.unavailable
            }
            if written == 0 { throw RelayError.closed }
            offset += written
        }
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

    static func peerProcess(fd: Int32) -> (uid: UInt32, pid: Int32)? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return nil }
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0 else {
            return nil
        }
        guard pid > 0 else { return nil }
        return (UInt32(uid), Int32(pid))
    }

    static func createListener(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RelayError.unavailable }
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
