import XCTest

final class HIbikiUITests: XCTestCase {
    func testSetupRequiresRelayAndDeviceName() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)"]
        app.launch()
        let start = app.buttons["getStarted"]
        XCTAssertTrue(start.waitForExistence(timeout: 10))
        XCTAssertFalse(start.isEnabled)
        app.textFields["relayURL"].tap()
        app.textFields["relayURL"].typeText("wss://example.com/hibiki")
        XCTAssertTrue(start.isEnabled)
        XCTAssertTrue(app.textFields["deviceName"].exists)
    }
}
