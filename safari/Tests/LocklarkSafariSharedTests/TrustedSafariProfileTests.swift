import XCTest
@testable import LocklarkSafariShared

/// `SFExtensionProfileKey` is a `UUID` in the native handler context. These are
/// pure value tests: no real Safari profile, environment or platform API is
/// read, and no string matching of the implementation is performed.
final class TrustedSafariProfileTests: XCTestCase {
    private let sample = UUID(
        uuidString: "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"
    )!

    func testMissingProfileStaysNil() throws {
        XCTAssertNil(try TrustedSafariProfile.identifier(nil))
    }

    func testUUIDBecomesLowercaseCanonicalIdentifier() throws {
        let identifier = try TrustedSafariProfile.identifier(sample)
        XCTAssertEqual(
            identifier,
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        )
        // The canonical form is also a valid bounded profile key for the
        // app-group hop.
        XCTAssertTrue(RelayEnvelope.isValidProfileKey(try XCTUnwrap(identifier)))
    }

    func testStringProfileIsRejectedAndNeverNil() {
        XCTAssertThrowsError(
            try TrustedSafariProfile.identifier(sample.uuidString)
        ) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
    }

    func testNullProfileIsRejectedAndNeverNil() {
        XCTAssertThrowsError(try TrustedSafariProfile.identifier(NSNull())) { error in
            XCTAssertEqual(error as? RelayError, .unavailable)
        }
    }
}
