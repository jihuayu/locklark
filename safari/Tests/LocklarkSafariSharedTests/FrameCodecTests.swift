import XCTest
@testable import LocklarkSafariShared

final class FrameCodecTests: XCTestCase {
    func testEncodingUsesLittleEndianLength() throws {
        let frame = try FrameCodec.encode(Data([0x7b, 0x7d]))
        XCTAssertEqual(Array(frame.prefix(4)), [2, 0, 0, 0])
        XCTAssertEqual(Array(frame.dropFirst(4)), [0x7b, 0x7d])
    }

    func testPartialAndMultipleFrames() throws {
        let first = try FrameCodec.encode(Data("a".utf8))
        let second = try FrameCodec.encode(Data("bc".utf8))
        var decoder = FrameDecoder()
        XCTAssertTrue(try decoder.append(Data(first.prefix(2))).isEmpty)
        let frames = try decoder.append(Data(first.dropFirst(2)) + second)
        XCTAssertEqual(frames.count, 2)
        XCTAssertEqual(String(data: frames[0], encoding: .utf8), "a")
        XCTAssertEqual(String(data: frames[1], encoding: .utf8), "bc")
    }

    func testOversizedFrameIsRejected() throws {
        let oversized = Data(repeating: 0x41, count: RelayLimits.maxFrameBytes + 1)
        XCTAssertThrowsError(try FrameCodec.encode(oversized))

        var header = Data([1, 0, 4, 0])
        header.append(Data(repeating: 0x41, count: 16))
        var decoder = FrameDecoder()
        XCTAssertThrowsError(try decoder.append(header))
        XCTAssertEqual(decoder.bufferedBytes, header.count)
    }

    func testEmptyFrameRoundTrip() throws {
        let encoded = try FrameCodec.encode(Data())
        var decoder = FrameDecoder()
        let frames = try decoder.append(encoded)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0], Data())
    }
}
