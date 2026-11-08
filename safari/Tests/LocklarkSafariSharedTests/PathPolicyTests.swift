import XCTest
@testable import LocklarkSafariShared

final class PathPolicyTests: XCTestCase {
    private let container = URL(
        fileURLWithPath: "/tmp/group.org.locklark.browser.safari",
        isDirectory: true
    )

    func testSocketPathIsFixedUnderContainer() {
        let socket = PathPolicy.relaySocketURL(container: container)
        XCTAssertEqual(
            socket.path,
            "/tmp/group.org.locklark.browser.safari/native/relay.sock"
        )
        XCTAssertNoThrow(
            try PathPolicy.validateRelaySocket(socket, container: container)
        )
    }

    func testArbitraryPathsAreRejected() {
        for candidate in [
            URL(fileURLWithPath: "/tmp/relay.sock"),
            container.appendingPathComponent("other/relay.sock"),
            container.appendingPathComponent("native/other.sock"),
            container.appendingPathComponent("native/../native/relay.sock"),
            URL(fileURLWithPath: "/tmp/group.org.locklark.browser.safari.evil/native/relay.sock"),
        ] {
            XCTAssertThrowsError(
                try PathPolicy.validateRelaySocket(
                    candidate,
                    container: container
                )
            )
        }
    }

    func testContainmentRejectsSiblingPrefix() {
        XCTAssertFalse(
            PathPolicy.isContained(
                URL(fileURLWithPath: "/tmp/group.org.locklark.browser.safari.evil/native/relay.sock"),
                in: container
            )
        )
        XCTAssertTrue(
            PathPolicy.isContained(
                PathPolicy.relaySocketURL(container: container),
                in: container
            )
        )
    }

    func testPlaceholderAppGroupIsRejected() {
        XCTAssertThrowsError(
            try PathPolicy.appGroupContainer(appGroupID: "$(APP_GROUP)")
        )
        XCTAssertThrowsError(
            try PathPolicy.appGroupContainer(appGroupID: "group.example.placeholder")
        )
    }
}
