import Foundation

public enum FrameCodecError: Error, Equatable {
    case frameTooLarge
    case truncated
    case invalidLength
}

/// Existing Locklark stdio framing: four-byte little-endian length followed by
/// one UTF-8 JSON frame. The Safari relay reuses it unchanged so the embedded
/// helper keeps one protocol.
public enum FrameCodec {
    public static func encode(_ payload: Data) throws -> Data {
        guard payload.count <= RelayLimits.maxFrameBytes else {
            throw FrameCodecError.frameTooLarge
        }
        var length = UInt32(payload.count).littleEndian
        var output = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        output.append(payload)
        return output
    }

    public static func encodeJSONObject(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw FrameCodecError.invalidLength
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [])
        return try encode(data)
    }
}

/// Incremental decoder with a hard per-frame and per-call bound. It never
/// buffers more than one maximum frame plus a partial header.
public struct FrameDecoder {
    private var buffer = Data()

    public init() {}

    public var bufferedBytes: Int { buffer.count }

    public mutating func append(_ data: Data) throws -> [Data] {
        buffer.append(data)
        var frames: [Data] = []
        while buffer.count >= MemoryLayout<UInt32>.size {
            let length = buffer.prefix(MemoryLayout<UInt32>.size)
                .withUnsafeBytes { raw in
                    raw.loadUnaligned(as: UInt32.self)
                }
                .littleEndian
            let size = Int(length)
            guard size <= RelayLimits.maxFrameBytes else {
                throw FrameCodecError.frameTooLarge
            }
            let total = MemoryLayout<UInt32>.size + size
            guard buffer.count >= total else { break }
            let payloadStart = buffer.index(buffer.startIndex, offsetBy: 4)
            let payloadEnd = buffer.index(payloadStart, offsetBy: size)
            frames.append(Data(buffer[payloadStart..<payloadEnd]))
            buffer.removeSubrange(buffer.startIndex..<payloadEnd)
            guard frames.count <= RelayLimits.maxFramesPerPoll else {
                throw FrameCodecError.frameTooLarge
            }
        }
        return frames
    }

    public mutating func reset() {
        buffer.removeAll(keepingCapacity: false)
    }
}
