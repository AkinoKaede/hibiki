/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Kaede Akino
 */

import XCTest
@testable import Hibiki

@MainActor
final class DevicePingTests: XCTestCase {
    private func eventually(_ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<100 {
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("State did not settle", file: file, line: line)
    }

    func testRollingWindowExcludesTimeoutsAndKeepsResultsOnStop() async throws {
        let ping = DevicePing()
        var count = 0
        ping.start(measure: { _ in
            count += 1
            return DevicePingReport(setupMicros: 9000, roundTripsMicros: [count == 35 ? nil : UInt64(count * 1000)])
        }, pause: { if count == 35 { ping.stop() } })
        try await eventually { count == 35 && !ping.isRunning }
        XCTAssertEqual(ping.samples.count, 30)
        XCTAssertEqual(ping.samples.first?.id, 5)
        XCTAssertNil(ping.samples.last?.microseconds)
        XCTAssertEqual(ping.averageMicros, 20_000)
        XCTAssertEqual(ping.setupMicros, 9000)
        XCTAssertEqual(ping.maxMilliseconds, 40.8, accuracy: 0.001)
        XCTAssertNil(ping.error)
    }

    func testStoppedRunCannotOverwriteRestartedMeasurements() async throws {
        let ping = DevicePing()
        var delayed: CheckedContinuation<DevicePingReport, Error>?
        ping.start(measure: { _ in try await withCheckedThrowingContinuation { delayed = $0 } })
        try await eventually { delayed != nil }
        ping.stop()
        ping.start(measure: { _ in DevicePingReport(setupMicros: 20, roundTripsMicros: [2000]) })
        try await eventually { ping.samples.count == 1 }
        delayed?.resume(returning: DevicePingReport(setupMicros: 999, roundTripsMicros: [999_000]))
        await Task.yield()
        ping.stop()
        XCTAssertEqual(ping.samples.count, 1)
        XCTAssertEqual(ping.samples.first?.microseconds, 2000)
        XCTAssertEqual(ping.setupMicros, 20)
    }

    func testAllTimeoutsAndConnectionFailureRetainMeaningfulState() async throws {
        let ping = DevicePing()
        var count = 0
        ping.start(measure: { _ in
            count += 1
            if count == 3 { throw NSError(domain: "Ping test", code: 1, userInfo: [NSLocalizedDescriptionKey: "Disconnected"]) }
            return DevicePingReport(setupMicros: 10, roundTripsMicros: [nil])
        }, pause: {})
        try await eventually { !ping.isRunning }
        XCTAssertEqual(ping.samples.count, 2)
        XCTAssertNil(ping.averageMicros)
        XCTAssertEqual(ping.maxMilliseconds, 1)
        XCTAssertEqual(ping.error, "Disconnected")
    }
}
