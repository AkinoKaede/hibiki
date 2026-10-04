import XCTest

@MainActor
final class HibikiUITests: XCTestCase {
    func testUnreachableRelayStaysOnSetupAfterRestart() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)"]
        app.launch()
        let relay = app.textFields["serverURL"]
        XCTAssertTrue(relay.waitForExistence(timeout: 10))
        relay.tap()
        relay.typeText("ws://127.0.0.1:1")
        app.buttons["getStarted"].tap()
        let alert = app.alerts["Unable to complete"]
        XCTAssertTrue(alert.waitForExistence(timeout: 20))
        XCTAssertTrue(alert.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Could not connect to the server.")).firstMatch.exists)
        alert.buttons["OK"].tap()
        XCTAssertTrue(app.buttons["getStarted"].isEnabled)
        XCTAssertFalse(app.tabBars.firstMatch.exists)
        app.terminate()
        app.launch()
        XCTAssertTrue(app.buttons["getStarted"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["getStarted"].isEnabled)
    }
    func testEmptyRelayAndAdvancedTLSOption() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)"]
        app.launch()
        let start = app.buttons["getStarted"]
        XCTAssertTrue(start.waitForExistence(timeout: 10))
        XCTAssertEqual(app.textFields["serverURL"].placeholderValue, "Server URL")
        XCTAssertFalse(start.isEnabled)
        XCTAssertFalse(app.switches["Skip TLS Certificate Validation"].exists)
        app.buttons["Advanced"].tap()
        let skip = app.switches["Skip TLS Certificate Validation"]
        XCTAssertTrue(skip.waitForExistence(timeout: 3))
        XCTAssertEqual(skip.value as? String, "0")
        XCTAssertFalse(start.isEnabled)
        app.textFields["serverURL"].tap()
        app.textFields["serverURL"].typeText("hibiki.example.com")
        XCTAssertTrue(start.isEnabled)
        XCTAssertTrue(app.textFields["hostname"].exists)
        XCTAssertEqual(app.textFields["hostname"].placeholderValue, "Hostname")
    }
}
