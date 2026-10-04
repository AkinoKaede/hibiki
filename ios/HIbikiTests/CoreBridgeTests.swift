import XCTest
@testable import HIbiki

final class CoreBridgeTests: XCTestCase {
    func testIdentitySurvivesReopeningAndServicesStartDisabled() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = try createIdentity(name: "iPhone test")
        let first = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, allowInsecure: false)
        let second = try MobileClient(directory: directory.path, server: "wss://example.com/hibiki", identity: identity, allowInsecure: false)
        XCTAssertEqual(try first.device().id, try second.device().id)
        XCTAssertEqual(try first.device().words.split(separator: " ").count, 24)
        XCTAssertNil(first.selectedCard())
        XCTAssertFalse(first.requestIsPending(token: "expired"))
        XCTAssertThrowsError(try first.respond(token: "expired", data: Data("PIN".utf8), accepted: true))
    }
    func testPlaintextRequiresExplicitOptIn() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let identity = try createIdentity(name: "test")
        XCTAssertThrowsError(try MobileClient(directory: directory.path, server: "ws://localhost:7749/hibiki", identity: identity, allowInsecure: false))
    }
    @MainActor
    func testInactiveSystemSheetDoesNotBackgroundApp() {
        let model = AppModel()
        model.foreground = true
        model.sceneChanged(.inactive)
        XCTAssertTrue(model.foreground)
        model.sceneChanged(.background)
        XCTAssertFalse(model.foreground)
    }
    func testInvalidIdentityFailsClosed() {
        XCTAssertThrowsError(try MobileClient(directory: "/tmp/hibiki-invalid", server: "wss://example.com/hibiki", identity: Data([1, 2, 3]), allowInsecure: false))
    }
}
