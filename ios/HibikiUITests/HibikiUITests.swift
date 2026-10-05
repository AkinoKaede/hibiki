import XCTest

@MainActor
final class HibikiUITests: XCTestCase {
    func testMembersOpenFullIdentityAndOfflinePingDetails() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture"]
        app.launch()
        let channels = app.tabBars.buttons["Channels"]
        XCTAssertTrue(channels.waitForExistence(timeout: 10))
        channels.tap()
        app.staticTexts["UI Test Channel"].tap()
        let id = String(repeating: "b", count: 64)
        let member = app.buttons["member-\(id)"]
        XCTAssertTrue(member.waitForExistence(timeout: 5))
        member.tap()
        let ping = app.buttons["memberPing"]
        XCTAssertTrue(ping.waitForExistence(timeout: 5))
        XCTAssertFalse(ping.isEnabled)
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Status unavailable")).firstMatch.exists)
        if !app.staticTexts[id].exists { app.swipeUp() }
        XCTAssertTrue(app.staticTexts[id].exists)
        app.swipeUp()
        if !app.staticTexts["word19 word20 word21 word22 word23 word24"].exists { app.swipeUp() }
        XCTAssertTrue(app.staticTexts["word19 word20 word21 word22 word23 word24"].exists)
        XCTAssertFalse(app.buttons["Revoke device"].exists)
        XCTAssertTrue(app.staticTexts["Outside your approval branch"].exists)
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Member details with complete identity"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
    func testSubtreeRevocationIsOptionalAndListsCompleteIdentities() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online"]
        app.launch()
        let channels = app.tabBars.buttons["Channels"]
        XCTAssertTrue(channels.waitForExistence(timeout: 10))
        channels.tap()
        app.staticTexts["UI Test Channel"].tap()
        let childID = String(repeating: "e", count: 64)
        let grandchildID = String(repeating: "f", count: 64)
        let member = app.buttons["member-\(childID)"]
        XCTAssertTrue(member.waitForExistence(timeout: 5))
        member.tap()
        for _ in 0..<3 where !app.buttons["Revoke device"].isHittable { app.swipeUp() }
        app.buttons["Revoke device"].tap()
        XCTAssertTrue(app.navigationBars["Review revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertFalse(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        app.buttons["Revoke entire approval subtree"].tap()
        XCTAssertTrue(app.navigationBars["Review revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertTrue(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.buttons["Revoke device"].exists)
    }
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
