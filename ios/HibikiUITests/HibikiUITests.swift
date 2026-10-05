import XCTest

@MainActor
final class HibikiUITests: XCTestCase {
    func testOperationNotificationOpensTheSelectedPrompt() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture", "--ui-operation-notification"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Selected Notification Request"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.secureTextFields["pinInput"].exists)
        XCTAssertFalse(app.navigationBars["Hibiki Request"].exists)
    }

    func testExpiredOperationNotificationDoesNotPresentAnotherRequest() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture", "--ui-operation-notification", "--ui-expired-notification"]
        app.launch()
        XCTAssertTrue(app.staticTexts["This request is no longer pending."].waitForExistence(timeout: 10))
        XCTAssertFalse(app.secureTextFields["pinInput"].exists)
        app.buttons["dismissUnavailableNotice"].tap()
        XCTAssertTrue(app.secureTextFields["pinInput"].waitForExistence(timeout: 5))
    }

    func testJoinNotificationOpensItsApprovalPage() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture", "--ui-join-notification"]
        app.launch()
        XCTAssertTrue(app.staticTexts["notification-request-id"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.navigationBars["Approve"].exists)
        XCTAssertTrue(app.staticTexts["Work Mac"].exists)
        XCTAssertTrue(app.buttons["scanAndApprove"].exists)
        XCTAssertFalse(app.buttons["Approve"].isEnabled)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        XCTAssertTrue(app.navigationBars["UI Test Channel"].waitForExistence(timeout: 5))
    }

    func testExpiredJoinNotificationStaysOnItsChannel() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture", "--ui-join-notification", "--ui-expired-notification"]
        app.launch()
        XCTAssertTrue(app.staticTexts["This request is no longer pending."].waitForExistence(timeout: 10))
        app.buttons["dismissUnavailableNotice"].tap()
        XCTAssertTrue(app.navigationBars["UI Test Channel"].exists)
        XCTAssertFalse(app.buttons["scanAndApprove"].exists)
    }

    func testBackgroundHidesPromptAndClearsUnsubmittedPINWithoutCanceling() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture"]
        app.launch()
        let input = app.secureTextFields["pinInput"]
        XCTAssertTrue(input.waitForExistence(timeout: 10))
        input.tap()
        input.typeText("123456")
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(input.waitForExistence(timeout: 10))
        XCTAssertFalse((input.value as? String ?? "").contains("•"))
        XCTAssertTrue(app.buttons["cancelPIN"].exists)
    }

    func testPendingChannelRemainsAccessibleAfterLeavingJoin() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture", "--ui-pending-fixture"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        XCTAssertTrue(app.staticTexts["Waiting for Approval"].exists)
        app.buttons["addChannel"].tap()
        app.buttons["joinChannel"].tap()
        XCTAssertTrue(app.images["pairingQRCode"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["scanInvitation"].exists)
        XCTAssertFalse(app.buttons["requestToJoin"].exists)
        app.buttons["cancelJoinChannel"].tap()
        app.staticTexts["UI Test Channel"].tap()
        let qr = app.images["pairingQRCode"]
        XCTAssertTrue(qr.waitForExistence(timeout: 5))
        XCTAssertEqual(qr.frame.midX, app.frame.midX, accuracy: 2)
        XCTAssertFalse(app.buttons["channelActions"].exists)
        XCTAssertFalse(app.staticTexts["Work Mac"].exists)
        for _ in 0..<3 where !app.buttons["Withdraw Request"].isHittable { app.swipeUp() }
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "pending-request-id")).firstMatch.exists)
        XCTAssertTrue(app.staticTexts["word19 word20 word21 word22 word23 word24"].exists)
        app.buttons["Withdraw Request"].tap()
        XCTAssertTrue(app.staticTexts["Withdraw this join request?"].waitForExistence(timeout: 5))
        app.buttons.matching(identifier: "Withdraw Request").allElementsBoundByIndex.first(where: { $0.isHittable })!.tap()
        XCTAssertTrue(app.staticTexts["Join this channel with a new invitation."].waitForExistence(timeout: 5))
        XCTAssertFalse(app.images["pairingQRCode"].exists)
        XCTAssertFalse(app.buttons["channelActions"].exists)
    }

    func testApprovedPendingChannelTransitionsToMembers() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture", "--ui-pending-fixture", "--ui-approve-pending"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        app.staticTexts["UI Test Channel"].tap()
        XCTAssertTrue(app.images["pairingQRCode"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["channelActions"].exists)
        app.navigationBars.buttons.element(boundBy: 0).tap()
        app.staticTexts["UI Test Channel"].tap()
        XCTAssertTrue(app.staticTexts["Work Mac"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["channelActions"].exists)
        XCTAssertFalse(app.images["pairingQRCode"].exists)
    }

    func testCreateChannelAndShareInvitationRemainPresented() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        app.buttons["addChannel"].tap()
        app.buttons["createChannel"].tap()
        let create = app.buttons["submitCreateChannel"]
        XCTAssertTrue(create.waitForExistence(timeout: 5))
        XCTAssertFalse(create.isEnabled)
        let name = app.textFields["channelName"]
        name.tap()
        name.typeText("   ")
        XCTAssertFalse(create.isEnabled)
        name.typeText("New Channel")
        XCTAssertTrue(create.isEnabled)
        create.tap()
        assertInvitationCanShareTwice(app)
        app.buttons["cancelInviteDevice"].tap()
        XCTAssertTrue(app.staticTexts["New Channel"].waitForExistence(timeout: 5))
        app.staticTexts["UI Test Channel"].tap()
        app.buttons["channelActions"].tap()
        app.buttons["inviteDevice"].tap()
        assertInvitationCanShareTwice(app)
        app.buttons["cancelInviteDevice"].tap()
        XCTAssertTrue(app.staticTexts["Work Mac"].waitForExistence(timeout: 5))
    }

    private func assertInvitationCanShareTwice(_ app: XCUIApplication) {
        let share = app.buttons["shareInvitation"]
        XCTAssertTrue(share.waitForExistence(timeout: 5))
        XCTAssertTrue(share.isEnabled)
        for _ in 0..<2 {
            share.tap()
            let close = app.buttons["header.closeButton"]
            XCTAssertTrue(close.waitForExistence(timeout: 5))
            // Cover the presentation transition that previously cleared the invitation.
            Thread.sleep(forTimeInterval: 2)
            XCTAssertTrue(close.isHittable)
            let screenshot = XCTAttachment(screenshot: app.screenshot())
            screenshot.name = "Invitation activity sheet remains open"
            screenshot.lifetime = .keepAlways
            add(screenshot)
            close.tap()
            XCTAssertTrue(app.buttons["shareInvitation"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.buttons["Copy Invitation"].exists)
        }
    }

    func testChannelPlusJoinsDirectlyWhenCreationIsDenied() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online", "--ui-invitations-fixture", "--ui-creation-denied"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        XCTAssertFalse(app.buttons["addChannel"].exists)
        app.buttons["joinChannel"].tap()
        XCTAssertTrue(app.navigationBars["Join Channel"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["createChannel"].exists)
        app.buttons["cancelJoinChannel"].tap()
        XCTAssertTrue(app.buttons["joinChannel"].waitForExistence(timeout: 5))
    }

    func testPhysicalNFCAndPinentryPresentationOrder() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("System NFC presentation requires an iPhone and a physical key")
        #else
        guard ProcessInfo.processInfo.environment["HIBIKI_PHYSICAL_NFC_TEST"] == "1" else {
            throw XCTSkip("Opt in with TEST_RUNNER_HIBIKI_PHYSICAL_NFC_TEST=1 and a physical key")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-nfc-order-fixture"]
        app.launch()
        let record = app.buttons["recordNFCKey"]
        XCTAssertTrue(record.waitForExistence(timeout: 10))
        record.tap()
        // Leave the key away initially so the system scanner is still open.
        Thread.sleep(forTimeInterval: 4)
        let during = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        during.name = "System NFC active with queued Pinentry confirmation"
        during.lifetime = .keepAlways
        add(during)
        print("NFC_ORDER_SCREEN: " + app.debugDescription)
        XCTAssertFalse(app.buttons["submitPIN"].isHittable, "Pinentry is covering the active system NFC scanner")
        // The operator can now tap a key or cancel the native scan.
        let visible = NSPredicate(format: "isHittable == true")
        expectation(for: visible, evaluatedWith: app.buttons["submitPIN"])
        waitForExpectations(timeout: 60)
        let after = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        after.name = "Pinentry confirmation after NFC closes"
        after.lifetime = .keepAlways
        add(after)
        app.buttons["submitPIN"].tap()
        XCTAssertTrue(app.buttons["submitPIN"].waitForNonExistence(timeout: 5))
        #endif
    }

    func testJoinToolbarAndAlignedMemberStatuses() {
        let app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-members-online"]
        app.launch()
        XCTAssertTrue(app.tabBars.buttons["Channels"].waitForExistence(timeout: 10))
        app.tabBars.buttons["Channels"].tap()
        XCTAssertFalse(app.buttons["addChannel"].exists)
        app.buttons["joinChannel"].tap()
        XCTAssertTrue(app.navigationBars["Join Channel"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["requestToJoin"].isEnabled)
        XCTAssertTrue(app.buttons["cancelJoinChannel"].isHittable)
        XCTAssertFalse(app.secureTextFields["Pre-Shared Key"].exists)
        app.buttons["scanInvitation"].tap()
        XCTAssertTrue(app.navigationBars["Scan Invitation"].waitForExistence(timeout: 5))
        if app.alerts.firstMatch.waitForExistence(timeout: 1) {
            let allow = app.alerts.buttons["Allow"]
            if allow.exists { allow.tap() } else { app.alerts.buttons.firstMatch.tap() }
        }
        XCTAssertTrue(app.buttons["chooseQRImage"].exists)
        app.navigationBars["Scan Invitation"].buttons["Cancel"].tap()
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

    func testNFCRecordControlsAndReadOnlyInspection() {
        for nfc in [false, true] {
            let app = XCUIApplication()
            app.launchArguments = ["-AppleLanguages", "(en)", "--ui-members-fixture", "--ui-cards-fixture"] + (nfc ? ["--ui-nfc"] : [])
            app.launch()
            XCTAssertTrue(app.tabBars.buttons["Security Keys"].waitForExistence(timeout: 10))
            XCTAssertEqual(app.buttons["recordNFCKey"].exists, nfc)
            if nfc {
                XCTAssertTrue(app.buttons["forgetNFCKey"].exists)
                app.buttons["forgetNFCKey"].tap()
                XCTAssertFalse(app.buttons["forgetNFCKey"].exists)
                XCTAssertEqual(app.buttons["recordNFCKey"].label, "Use NFC Key")
            }
            app.tabBars.buttons["Security Keys"].tap()
            XCTAssertEqual(app.segmentedControls["inspectionTransport"].exists, nfc)
            let read = app.buttons["readSecurityKeyInfo"]
            XCTAssertEqual(read.label, "Read USB Information")
            XCTAssertTrue(read.isEnabled)
            XCTAssertTrue(read.isHittable)
            XCTAssertFalse(app.buttons["registerSecurityKey"].exists)
            XCTAssertFalse(app.buttons["recordNFCKey"].exists)
            XCTAssertFalse(app.buttons["editSecurityKey"].exists)
            app.terminate()
            app.launchArguments.removeAll { $0 == "--ui-cards-fixture" }
            app.launch()
            XCTAssertTrue(app.tabBars.buttons["Security Keys"].waitForExistence(timeout: 10))
            XCTAssertFalse(app.buttons["forgetNFCKey"].exists)
            app.terminate()
        }
    }

    func testOnlyInsertionConfirmOffersNFCFallback() {
        for arguments in [["--ui-nfc", "--ui-confirm"], ["--ui-nfc", "--ui-ordinary-confirm"], ["--ui-nfc", "--ui-confirm", "--ui-message"], ["--ui-confirm"]] {
            let app = XCUIApplication()
            app.launchArguments = ["-AppleLanguages", "(en)", "--ui-pin-fixture"] + arguments
            app.launch()
            XCTAssertTrue(app.buttons["submitPIN"].waitForExistence(timeout: 10))
            XCTAssertTrue(app.buttons["submitPIN"].isEnabled)
            let insertion = arguments == ["--ui-nfc", "--ui-confirm"]
            XCTAssertEqual(app.staticTexts["insertionNFCHint"].exists, insertion)
            XCTAssertFalse(app.buttons["recordNFCKey"].isHittable)
            if !insertion {
                app.buttons["submitPIN"].tap()
                XCTAssertTrue(app.buttons["submitPIN"].waitForNonExistence(timeout: 5))
            }
            app.terminate()
        }
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
        XCTAssertFalse(app.buttons["Revoke"].exists)
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
        for _ in 0..<3 where !app.buttons["Revoke"].isHittable { app.swipeUp() }
        app.buttons["Revoke"].tap()
        XCTAssertTrue(app.navigationBars["Review Revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertFalse(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        app.buttons["Revoke Entire Approval Subtree"].tap()
        XCTAssertTrue(app.navigationBars["Review Revocation"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[childID].exists)
        XCTAssertTrue(app.staticTexts[grandchildID].exists)
        app.buttons["Cancel"].tap()
        XCTAssertTrue(app.buttons["Revoke"].exists)
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
