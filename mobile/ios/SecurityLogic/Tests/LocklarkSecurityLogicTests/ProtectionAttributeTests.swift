import Foundation
import XCTest
@testable import LocklarkSecurityLogic

final class ProtectionAttributeTests: XCTestCase {
    func testExactCompleteValueAcceptsFoundationRepresentations() {
        XCTAssertTrue(ProtectionAttribute.isComplete(FileProtectionType.complete))
        XCTAssertTrue(ProtectionAttribute.isComplete(FileProtectionType.complete.rawValue))
        XCTAssertTrue(ProtectionAttribute.isComplete(FileProtectionType.complete.rawValue as NSString))
    }

    func testLessProtectedValuesAreAlwaysRejected() {
        for value in [FileProtectionType.none, .completeUnlessOpen, .completeUntilFirstUserAuthentication] {
            XCTAssertFalse(ProtectionAttribute.isComplete(value))
            XCTAssertFalse(ProtectionAttribute.isComplete(value.rawValue))
        }
    }

    func testMissingOrSimilarStringsAreNeverTreatedAsComplete() {
        for value: Any? in [nil, NSNull(), true, "complete", " NSFileProtectionComplete", "NSFileProtectionComplete ", "nsfileprotectioncomplete"] {
            XCTAssertFalse(ProtectionAttribute.isComplete(value))
        }
    }
}
