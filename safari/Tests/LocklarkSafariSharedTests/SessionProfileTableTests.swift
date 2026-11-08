import XCTest
@testable import LocklarkSafariShared

/// Exact Optional profile matching: a token plus the wrong profile (or a nil
/// profile against a profiled session) must never reach a session, and a
/// mismatched close must leave the session in place.
final class SessionProfileTableTests: XCTestCase {
    private final class FakeSession {
        var closed = false
        func close() { closed = true }
    }

    private let token = "0123456789abcdef0123456789abcdef"

    func testMatchingProfileReachesSession() {
        var table = SessionProfileTable<FakeSession>()
        let session = FakeSession()
        XCTAssertNil(table.bind(token: token, profile: "Profile A", session: session))
        XCTAssertTrue(table.session(token: token, profile: "Profile A") === session)
    }

    func testOtherProfileIsRejected() {
        var table = SessionProfileTable<FakeSession>()
        let session = FakeSession()
        _ = table.bind(token: token, profile: "Profile A", session: session)
        XCTAssertNil(table.session(token: token, profile: "Profile B"))
        XCTAssertEqual(table.count, 1)
    }

    func testNilProfileOnlyMatchesNilBindingInBothDirections() {
        var table = SessionProfileTable<FakeSession>()
        let profiled = FakeSession()
        _ = table.bind(token: token, profile: "Profile A", session: profiled)
        // nil cannot reach a profiled session ...
        XCTAssertNil(table.session(token: token, profile: nil))
        XCTAssertNil(table.remove(token: token, profile: nil))
        XCTAssertEqual(table.count, 1)

        // ... and a profile cannot reach a nil-bound session.
        var nilTable = SessionProfileTable<FakeSession>()
        let unprofiled = FakeSession()
        _ = nilTable.bind(token: token, profile: nil, session: unprofiled)
        XCTAssertTrue(nilTable.session(token: token, profile: nil) === unprofiled)
        XCTAssertNil(nilTable.session(token: token, profile: "Profile A"))
        XCTAssertNil(nilTable.remove(token: token, profile: "Profile A"))
        XCTAssertEqual(nilTable.count, 1)
    }

    func testMismatchedClosePreservesSession() {
        var table = SessionProfileTable<FakeSession>()
        let session = FakeSession()
        _ = table.bind(token: token, profile: "Profile A", session: session)
        XCTAssertNil(table.remove(token: token, profile: "Profile B"))
        XCTAssertNil(table.remove(token: token, profile: nil))
        XCTAssertEqual(table.count, 1)
        XCTAssertFalse(session.closed)
        // The exact binding still closes and only then removes.
        XCTAssertTrue(table.remove(token: token, profile: "Profile A") === session)
        XCTAssertEqual(table.count, 0)
    }

    func testRebindReturnsDisplacedSessionOnly() {
        var table = SessionProfileTable<FakeSession>()
        let first = FakeSession()
        let second = FakeSession()
        XCTAssertNil(table.bind(token: token, profile: "Profile A", session: first))
        XCTAssertTrue(
            table.bind(token: token, profile: "Profile B", session: second) === first
        )
        XCTAssertNil(table.session(token: token, profile: "Profile A"))
        XCTAssertTrue(table.session(token: token, profile: "Profile B") === second)
    }

    func testBoundedCountAndExtraction() {
        var table = SessionProfileTable<FakeSession>()
        let one = FakeSession()
        let two = FakeSession()
        _ = table.bind(token: token, profile: nil, session: one)
        _ = table.bind(
            token: "fedcba9876543210fedcba9876543210",
            profile: "Profile A",
            session: two
        )
        XCTAssertEqual(table.count, 2)
        let extracted = table.extract { $0 === two }
        XCTAssertEqual(extracted.count, 1)
        XCTAssertTrue(extracted.first === two)
        XCTAssertEqual(table.count, 1)
        let remaining = table.removeAll()
        XCTAssertEqual(remaining.count, 1)
        XCTAssertTrue(remaining.first === one)
        XCTAssertEqual(table.count, 0)
    }
}
