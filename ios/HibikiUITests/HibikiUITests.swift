import XCTest

@MainActor
final class HibikiUITests: XCTestCase {
    func testJoinToolbarAndAlignedMemberStatuses() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        app.buttons["joinChannel"].tap()
        XCTAssertTrue(app.navigationBars["Join Channel"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["requestToJoin"].isEnabled)
        XCTAssertTrue(app.buttons["cancelJoinChannel"].isHittable)
        app.buttons["cancelJoinChannel"].tap()
        app.staticTexts["UI Test Channel"].tap()
        let phone = app.staticTexts["Fixture iPhone"]
        let mac = app.staticTexts["Work Mac"]
        XCTAssertTrue(mac.waitForExistence(timeout: 5))
        XCTAssertEqual(phone.frame.minX, mac.frame.minX, accuracy: 1)
        XCTAssertTrue(app.staticTexts["This Device"].exists)
        let list = XCTAttachment(screenshot: app.screenshot())
        list.name = "Aligned device names and online status"
        list.lifetime = .keepAlways
        add(list)
        app.buttons["channelActions"].tap()
        app.buttons["inviteDevice"].tap()
        XCTAssertTrue(app.buttons["cancelInviteDevice"].waitForExistence(timeout: 3))
        app.buttons["cancelInviteDevice"].tap()
        XCTAssertTrue(app.staticTexts["Work Mac"].waitForExistence(timeout: 3))
        app.buttons["member-\(String(repeating: "b", count: 64))"].tap()
        let status = app.cells.containing(.staticText, identifier: "Status").firstMatch
        XCTAssertTrue(status.waitForExistence(timeout: 3))
        XCTAssertLessThan(status.frame.height, 70)
        XCTAssertTrue(app.staticTexts["Approved by"].exists)
        XCTAssertTrue(app.buttons["memberPing"].isHittable)
        let detail = XCTAttachment(screenshot: app.screenshot())
        detail.name = "Compact online device details"
        detail.lifetime = .keepAlways
        add(detail)
    }

    func testNFCControlsFollowCapabilityAndEditUsesIconActions() {
        for nfc in [false, true] {
            let app = XCUIApplication()
            app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-cards-fixture"] + (nfc ? ["--ui-nfc"] : [])
            app.launch()
            XCTAssertTrue(app.tabBars.buttons["Security Keys"].waitForExistence(timeout: 10))
            app.tabBars.buttons["Security Keys"].tap()
            XCTAssertEqual(app.segmentedControls["inspectionTransport"].exists, nfc)
            XCTAssertEqual(app.buttons["registerSecurityKey"].exists, nfc)
            XCTAssertFalse(app.buttons["registerUSB"].exists)
            if nfc {
                app.buttons["registerSecurityKey"].tap()
                XCTAssertTrue(app.buttons["Read and Register"].waitForExistence(timeout: 3))
                XCTAssertFalse(app.switches["USB Connection Support"].exists)
                XCTAssertFalse(app.switches["NFC Support"].exists)
                app.navigationBars.buttons.firstMatch.tap()
            }
            app.staticTexts["Fixture Security Key"].tap()
            XCTAssertFalse(app.staticTexts["Selected Security Key"].exists)
            XCTAssertFalse(app.buttons["Use This Security Key"].exists)
            app.buttons["editSecurityKey"].tap()
            XCTAssertTrue(app.buttons["saveSecurityKey"].waitForExistence(timeout: 3))
            XCTAssertFalse(app.switches["securityKeyNFC"].exists)
            XCTAssertFalse(app.switches["securityKeyUSB"].exists)
            XCTAssertTrue(app.buttons["Cancel"].isHittable)
            let screenshot = XCTAttachment(screenshot: app.screenshot())
            screenshot.name = nfc ? "Edit on NFC-capable device" : "Edit on USB-only device"
            screenshot.lifetime = .keepAlways
            add(screenshot)
            app.buttons["Cancel"].tap()
            app.terminate()
        }
    }

    func testStatusNFCSelectionCanBeClearedAndDoesNotSurviveRelaunch() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-cards-fixture", "--ui-nfc", "--ui-multiple-nfc"]
        app.launch()
        let key = app.buttons["nfcCard-D2760001240103040005000012340000"]
        XCTAssertTrue(key.waitForExistence(timeout: 10))
        XCTAssertEqual(key.value as? String, "Not Selected")
        XCTAssertTrue(app.staticTexts["0005 00001234"].exists)
        XCTAssertTrue(app.staticTexts["12 080 862"].exists)
        let second = app.buttons["nfcCard-D2760001240100000006120808620000"]
        key.tap()
        second.tap()
        XCTAssertEqual(key.value as? String, "Not Selected")
        XCTAssertEqual(second.value as? String, "Selected")
        second.tap()
        XCTAssertEqual(second.value as? String, "Not Selected")
        XCTAssertFalse(app.staticTexts["Connect via USB, or enter the PIN and tap with NFC."].exists)
        key.tap()
        XCTAssertEqual(key.value as? String, "Selected")
        key.tap()
        XCTAssertEqual(key.value as? String, "Not Selected")
        key.tap()
        app.terminate()
        app.launch()
        XCTAssertTrue(key.waitForExistence(timeout: 10))
        XCTAssertEqual(key.value as? String, "Not Selected")
    }

    func testInsertionConfirmationAllowsNFCSelectionBeforeOK() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture", "--ui-nfc", "--ui-confirm"]
        app.launch()
        let key = app.buttons["nfcCard-D2760001240103040005000012340000"].firstMatch
        XCTAssertTrue(app.buttons["submitPIN"].waitForExistence(timeout: 10))
        XCTAssertTrue(key.isHittable)
        XCTAssertEqual(key.value as? String, "Not Selected")
        key.tap()
        XCTAssertEqual(key.value as? String, "Selected")
        XCTAssertTrue(app.buttons["submitPIN"].isHittable)
        app.buttons["submitPIN"].tap()
        XCTAssertTrue(app.buttons["submitPIN"].waitForNonExistence(timeout: 5))
        XCTAssertEqual(app.buttons["nfcCard-D2760001240103040005000012340000"].value as? String, "Selected")
    }

    func testPINUsesOnlyCloseButtonToCancel() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture", "--ui-nfc"]
        app.launch()
        let ok = app.buttons["submitPIN"]
        let close = app.buttons["cancelPIN"]
        XCTAssertTrue(ok.waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["nfcCard-D2760001240103040005000012340000"].isHittable)
        XCTAssertFalse(app.buttons["cancelOperation"].exists)
        XCTAssertTrue(close.isHittable)
        XCTAssertEqual(close.label, "Cancel")
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "PIN with a single close button for cancellation"
        screenshot.lifetime = .keepAlways
        add(screenshot)
        close.tap()
        XCTAssertTrue(ok.waitForNonExistence(timeout: 5))
    }
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
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Status Unavailable")).firstMatch.exists)
        if !app.staticTexts[id].exists { app.swipeUp() }
        XCTAssertTrue(app.staticTexts[id].exists)
        app.swipeUp()
        if !app.staticTexts["word19 word20 word21 word22 word23 word24"].exists { app.swipeUp() }
        XCTAssertTrue(app.staticTexts["word19 word20 word21 word22 word23 word24"].exists)
        XCTAssertFalse(app.buttons["Revoke Device"].exists)
        XCTAssertTrue(app.staticTexts["Outside Your Approval Branch"].exists)
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
        for _ in 0..<3 where !app.buttons["Revoke Device"].isHittable { app.swipeUp() }
        app.buttons["Revoke Device"].tap()
        XCTAssertTrue(app.navigationBars["Review Revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertFalse(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        app.buttons["Revoke Entire Approval Subtree"].tap()
        XCTAssertTrue(app.navigationBars["Review Revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertTrue(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.buttons["Revoke Device"].exists)
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
        let alert = app.alerts["Unable to Complete"]
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
