import XCTest
@testable import LocklarkSafariShared

/// The minimal helper environment is a pure function of its two arguments, so
/// these checks never read the test host's real environment and never observe a
/// credential or proxy value. They only prove that the child receives exactly
/// the fixed baseline and nothing else.
final class HelperEnvironmentTests: XCTestCase {
    private let home = "/Users/example"
    private let temporaryDirectory = "/var/folders/aa/bbbb/T/"

    func testBaselineHasExactlyThreeFixedKeys() {
        let environment = HelperEnvironment.minimal(
            home: home,
            temporaryDirectory: temporaryDirectory
        )
        XCTAssertEqual(
            Set(environment.keys),
            Set(["HOME", "TMPDIR", "PATH"])
        )
    }

    func testBaselineValuesComeOnlyFromTheOSArguments() {
        let environment = HelperEnvironment.minimal(
            home: home,
            temporaryDirectory: temporaryDirectory
        )
        XCTAssertEqual(environment["HOME"], home)
        XCTAssertEqual(environment["TMPDIR"], temporaryDirectory)
        XCTAssertEqual(environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        XCTAssertEqual(HelperEnvironment.path, "/usr/bin:/bin:/usr/sbin:/sbin")
    }

    func testNoAmbientInheritanceSurvivesThePolicy() {
        let environment = HelperEnvironment.minimal(
            home: home,
            temporaryDirectory: temporaryDirectory
        )
        // Names, not values: a leaked token/DYLD/proxy/socket override would
        // appear as an extra key, so absence is checked without reading one.
        for forbidden in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "SSH_AUTH_SOCK",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "LOCKLARK_BROWSER_SOCKET",
            "LOCKLARK_CONFIG",
            "XDG_CONFIG_HOME",
        ] {
            XCTAssertNil(environment[forbidden], forbidden)
        }
        XCTAssertEqual(environment.count, 3)
    }

    func testDifferentInputsCannotReuseAnotherUsersHome() {
        let first = HelperEnvironment.minimal(
            home: home,
            temporaryDirectory: temporaryDirectory
        )
        let second = HelperEnvironment.minimal(
            home: "/Users/other",
            temporaryDirectory: "/private/var/folders/cc/dddd/T/"
        )
        XCTAssertEqual(first["PATH"], second["PATH"])
        XCTAssertNotEqual(first["HOME"], second["HOME"])
        XCTAssertNotEqual(first["TMPDIR"], second["TMPDIR"])
    }
}
