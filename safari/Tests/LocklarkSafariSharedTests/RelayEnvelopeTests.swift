import XCTest
@testable import LocklarkSafariShared

final class RelayEnvelopeTests: XCTestCase {
    private let token = "0123456789abcdef0123456789abcdef"

    func testAllOperationsParse() throws {
        for operation in ["open", "poll", "close"] {
            let request = RelayRequest.parse([
                "v": 1,
                "op": operation,
                "token": token,
            ])
            XCTAssertEqual(request?.operation.rawValue, operation)
            XCTAssertEqual(request?.token, token)
            XCTAssertNil(request?.frame)
        }
        let send = RelayRequest.parse([
            "v": 1,
            "op": "send",
            "token": token,
            "frame": ["v": 1, "id": "abc", "type": "hello"],
        ])
        XCTAssertEqual(send?.operation, .send)
        XCTAssertEqual(send?.frame?["type"] as? String, "hello")
    }

    func testUnknownKeysAndBadFieldsAreRefused() {
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "send", "token": token,
            "frame": ["v": 1], "extra": true,
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": true, "op": "open", "token": token,
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "open", "token": token.uppercased(),
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "open", "token": String(token.dropLast()),
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "delete", "token": token,
        ]))
        XCTAssertNil(RelayRequest.parse("not-a-dictionary"))
    }

    func testOversizedAndNonJSONFramesAreRefused() {
        XCTAssertNil(RelayRequest.parse([
            "v": 1,
            "op": "send",
            "token": token,
            "frame": [
                "v": 1,
                "pad": String(repeating: "x", count: RelayLimits.maxFrameBytes + 1),
            ],
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "send", "token": token,
            "frame": ["v": 1, "bad": Date()],
        ]))
    }

    func testBrowserEnvelopeRefusesAnyProfileField() {
        // JS/page content must never choose or spoof a profile binding.
        for operation in ["open", "poll", "close"] {
            XCTAssertNil(RelayRequest.parse([
                "v": 1,
                "op": operation,
                "token": token,
                "profile": "default-profile",
            ]))
        }
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "send", "token": token,
            "frame": ["v": 1], "profile": "x",
        ]))
        XCTAssertNil(RelayRequest.parse([
            "v": 1, "op": "open", "token": token, "profile": NSNull(),
        ]))
    }

    func testNativeEnvelopeCarriesProfileOnEveryOperation() {
        for operation in ["open", "poll", "close"] {
            let request = RelayRequest.parseNative([
                "v": 1,
                "op": operation,
                "token": token,
                "profile": "Profile One",
            ])
            XCTAssertEqual(request?.operation.rawValue, operation)
            XCTAssertEqual(request?.profileKey, "Profile One")
        }
        let send = RelayRequest.parseNative([
            "v": 1, "op": "send", "token": token,
            "frame": ["v": 1, "type": "hello"],
            "profile": "Profile One",
        ])
        XCTAssertEqual(send?.frame?["type"] as? String, "hello")
        XCTAssertEqual(send?.profileKey, "Profile One")
        // Safari without profiles forwards no profile; it stays nil and is
        // only ever compared against other nil profiles.
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token,
        ])?.profileKey)
    }

    func testNativeProfileBoundsAndUnknownKeysFailClosed() {
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token,
            "profile": String(
                repeating: "p",
                count: RelayLimits.maxProfileBytes + 1
            ),
        ]))
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token,
            "profile": "bad\u{0}profile",
        ]))
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token, "profile": "",
        ]))
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token, "profile": 7,
        ]))
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "poll", "token": token,
            "profile": "p", "extra": 1,
        ]))
        XCTAssertNil(RelayRequest.parseNative([
            "v": 1, "op": "send", "token": token, "profile": "p",
        ]))
    }

    func testForwardingEnvelopeForwardsNativeProfileOnAllOperations() {
        for operation in ["open", "send", "poll", "close"] {
            let raw: [String: Any] = operation == "send"
                ? ["v": 1, "op": operation, "token": token, "frame": ["v": 1]]
                : ["v": 1, "op": operation, "token": token]
            guard let request = RelayRequest.parse(raw) else {
                return XCTFail("browser envelope must parse")
            }
            let forwarded = request.forwardingEnvelope(profileKey: "Profile One")
            XCTAssertEqual(forwarded["profile"] as? String, "Profile One")
            XCTAssertNotNil(RelayRequest.parseNative(forwarded))
            // The browser parser still refuses the same envelope.
            XCTAssertNil(RelayRequest.parse(forwarded))
        }
    }

    func testForwardingEnvelopeDropsUnknownKeys() {
        let request = RelayRequest.parse([
            "v": 1, "op": "open", "token": token,
        ])!
        let forwarded = request.forwardingEnvelope(profileKey: "Profile One")
        XCTAssertEqual(Set(forwarded.keys), Set(["v", "op", "token", "profile"]))
        XCTAssertEqual(forwarded["profile"] as? String, "Profile One")
        // An invalid profile is never forwarded.
        let dropped = request.forwardingEnvelope(
            profileKey: String(repeating: "p", count: 4096)
        )
        XCTAssertNil(dropped["profile"])
    }

    func testReplySuccessAndFailureShapes() throws {
        let success = RelayReply.success(
            token: token,
            frames: [["v": 1, "id": "a", "type": "locked"]]
        )
        XCTAssertEqual(Set(success.keys), Set(["v", "token", "ok", "frames"]))
        let parsed = try XCTUnwrap(
            RelayReply.parse(success, expectedToken: token)
        )
        XCTAssertEqual((parsed["frames"] as? [[String: Any]])?.count, 1)

        let failure = RelayReply.failure(token: token)
        XCTAssertEqual(Set(failure.keys), Set(["v", "token", "ok"]))
        XCTAssertNil(failure["frames"])
        XCTAssertNil(failure["error"])
    }

    func testReplyParserRefusesUnknownOrMismatchedReplies() {
        XCTAssertNil(RelayReply.parse(
            ["v": 1, "token": token, "ok": true, "frames": [], "error": "x"],
            expectedToken: token
        ))
        XCTAssertNil(RelayReply.parse(
            ["v": 1, "token": String(token.reversed()), "ok": true, "frames": []],
            expectedToken: token
        ))
        XCTAssertNil(RelayReply.parse(
            ["v": 1, "token": token, "ok": false, "frames": []],
            expectedToken: token
        ))
        XCTAssertNil(RelayReply.parse(
            ["v": 1, "token": token, "ok": true],
            expectedToken: token
        ))
        XCTAssertNil(RelayReply.parse(
            [
                "v": 1, "token": token, "ok": true,
                "frames": Array(
                    repeating: ["v": 1],
                    count: RelayLimits.maxFramesPerPoll + 1
                ),
            ],
            expectedToken: token
        ))
    }

    func testProfileValidation() {
        XCTAssertTrue(RelayEnvelope.isValidProfileKey("default"))
        XCTAssertFalse(RelayEnvelope.isValidProfileKey(""))
        XCTAssertFalse(RelayEnvelope.isValidProfileKey("bad\u{7f}"))
        XCTAssertFalse(
            RelayEnvelope.isValidProfileKey(
                String(repeating: "p", count: 257)
            )
        )
    }
}
