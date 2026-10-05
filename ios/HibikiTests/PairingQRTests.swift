/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import XCTest
import UIKit
@testable import Hibiki

final class PairingQRTests: XCTestCase {
    func testInvitationAndVerificationImagesRoundTripThroughVision() throws {
        for prefix in ["hibiki-invite-v2:", "hibiki-verify-v1:"] {
            for length in [80, 500, 1000] {
                let payload = prefix + String(repeating: "Abcd0123_-", count: length / 10)
                let image = try XCTUnwrap(PairingQR.image(payload))
                let bytes = try XCTUnwrap(image.pngData())
                XCTAssertEqual(try PairingQR.read(bytes), [payload])
            }
        }
    }
    func testImageWithoutACodeDoesNotInventAnInvitation() throws {
        let image = UIGraphicsImageRenderer(size: CGSize(width: 200, height: 200)).image { context in
            UIColor.white.setFill(); context.fill(CGRect(x: 0, y: 0, width: 200, height: 200))
        }
        XCTAssertTrue(try PairingQR.read(XCTUnwrap(image.pngData())).isEmpty)
    }
    func testInvalidImageIsRejected() {
        XCTAssertThrowsError(try PairingQR.read(Data("not an image".utf8)))
    }
}
