import XCTest
@testable import LocklarkSecurityLogic

final class VisibleTextTests: XCTestCase {
    func testTitlesExposeBidiAndFormatControlsWithoutChangingStoredText() {
        let stored = "raw\u{202e}\u{2066}\u{200d}\n\t中文"
        let shown = VisibleText.title(stored)
        XCTAssertTrue(shown == "raw\\u{202e}\\u{2066}\\u{200d}\\u{a}\\u{9}中文", "title controls must be visible escapes")
        XCTAssertTrue(stored.unicodeScalars.contains { $0.value == 0x202e }, "rendering must not rewrite storage")
    }

    func testSecretNotesKeepLinesButExposeFormatControls() {
        XCTAssertTrue(VisibleText.secret("line\n\t\u{202e}") == "line\n\t\\u{202e}", "plain-text display must preserve intended lines")
    }
}
