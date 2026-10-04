import XCTest

final class HIbikiUITests: XCTestCase {
    func testDefaultRelayAndAdvancedTLSOption() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)"]
        app.launch()
        let start = app.buttons["getStarted"]
        XCTAssertTrue(start.waitForExistence(timeout: 10))
        XCTAssertEqual(app.textFields["relayURL"].value as? String, "wss://hibiki.akinokaede.com/hibiki")
        XCTAssertFalse(app.switches["Skip TLS Certificate Validation"].exists)
        app.buttons["Advanced"].tap()
        let skip = app.switches["Skip TLS Certificate Validation"]
        XCTAssertTrue(skip.waitForExistence(timeout: 3))
        XCTAssertEqual(skip.value as? String, "0")
        XCTAssertTrue(start.isEnabled)
        XCTAssertTrue(app.textFields["deviceName"].exists)
    }
}
