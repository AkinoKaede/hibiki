import SwiftUI
import Observation

struct PingSample: Identifiable {
    let id: Int
    let microseconds: UInt64?
    let date: Date
}

@MainActor @Observable
final class DevicePing {
    private(set) var samples: [PingSample] = []
    private(set) var setupMicros: UInt64?
    private(set) var isRunning = false
    private(set) var error: String?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var cancellation: PingCancellation?
    private var run: UUID?
    private var nextIndex = 0
    var averageMicros: Double? {
        let values = samples.compactMap(\.microseconds).map { Double($0) }
        return values.isEmpty ? nil : values.reduce(0, +) / Double(values.count)
    }
    var maxMilliseconds: Double { max((samples.compactMap(\.microseconds).max().map { Double($0) } ?? 0) / 1000 * 1.2, 1) }

    func start(measure: @escaping (PingCancellation) async throws -> DevicePingReport,
               pause: @escaping () async throws -> Void = { try await Task.sleep(for: .seconds(1)) }) {
        stop()
        samples = []; setupMicros = nil; error = nil; nextIndex = 0
        let id = UUID()
        let cancellation = PingCancellation()
        run = id; self.cancellation = cancellation; isRunning = true
        task = Task {
            defer { if run == id { stop() } }
            do {
                while !Task.isCancelled, run == id {
                    let report = try await measure(cancellation)
                    guard !Task.isCancelled, run == id else { return }
                    setupMicros = report.setupMicros
                    for value in report.roundTripsMicros {
                        samples.append(PingSample(id: nextIndex, microseconds: value, date: Date()))
                        nextIndex += 1
                    }
                    if samples.count > 30 { samples.removeFirst(samples.count - 30) }
                    try await pause()
                }
            } catch {
                if !Task.isCancelled, run == id { self.error = error.localizedDescription }
            }
        }
    }
    func stop() {
        run = nil; isRunning = false
        cancellation?.cancel(); cancellation = nil
        task?.cancel(); task = nil
    }
    static func milliseconds(_ value: Double) -> String { String(format: "%.2f ms", value / 1000) }
}

struct PingChart: View {
    let samples: [PingSample]
    let maximum: Double
    var body: some View {
        HStack(spacing: 8) {
            Canvas { context, size in
                for index in 0...3 {
                    let y = size.height * CGFloat(index) / 3
                    var grid = Path()
                    grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: size.width, y: y))
                    context.stroke(grid, with: .color(.secondary.opacity(0.3)), style: StrokeStyle(lineWidth: 1, dash: [5, 5]))
                }
                var points: [CGPoint] = []
                func drawSegment() {
                    guard let first = points.first, let last = points.last else { return }
                    var line = Path(); line.move(to: first)
                    for point in points.dropFirst() { line.addLine(to: point) }
                    var area = line
                    area.addLine(to: CGPoint(x: last.x, y: size.height))
                    area.addLine(to: CGPoint(x: first.x, y: size.height)); area.closeSubpath()
                    context.fill(area, with: .color(.blue.opacity(0.1)))
                    context.stroke(line, with: .color(.blue), style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                    if points.count == 1 {
                        context.fill(Path(ellipseIn: CGRect(x: first.x - 2, y: first.y - 2, width: 4, height: 4)), with: .color(.blue))
                    }
                    points.removeAll()
                }
                for (index, sample) in samples.enumerated() {
                    let x = samples.count == 1 ? size.width / 2 : 2 + (size.width - 4) * CGFloat(index) / CGFloat(samples.count - 1)
                    if let value = sample.microseconds {
                        points.append(CGPoint(x: x, y: size.height * (1 - min(Double(value) / 1000 / maximum, 1))))
                    } else {
                        drawSegment()
                        var cross = Path()
                        cross.move(to: CGPoint(x: x - 3, y: size.height - 6)); cross.addLine(to: CGPoint(x: x + 3, y: size.height))
                        cross.move(to: CGPoint(x: x + 3, y: size.height - 6)); cross.addLine(to: CGPoint(x: x - 3, y: size.height))
                        context.stroke(cross, with: .color(.orange), lineWidth: 1.5)
                    }
                }
                drawSegment()
            }
            VStack(alignment: .trailing, spacing: 0) {
                ForEach((0...3).reversed(), id: \.self) { index in
                    Text(verbatim: String(format: maximum < 10 ? "%.1f ms" : "%.0f ms", maximum * Double(index) / 3))
                    if index != 0 { Spacer(minLength: 0) }
                }
            }.font(.caption2).monospacedDigit().foregroundStyle(.secondary)
        }
        .frame(height: 80)
        .alignmentGuide(.listRowSeparatorLeading) { _ in 0 }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Ping History")
        .accessibilityValue(samples.map { $0.microseconds.map { DevicePing.milliseconds(Double($0)) } ?? String(localized: "Timed Out") }.joined(separator: ", "))
        .accessibilityIdentifier("pingChart")
    }
}

struct DevicePingSection: View {
    let ping: DevicePing
    let canPing: Bool
    let start: () -> Void
    var body: some View {
        Section {
            if let latest = ping.samples.last {
                LabeledContent("Current RTT", value: latest.microseconds.map { DevicePing.milliseconds(Double($0)) } ?? String(localized: "Timed Out"))
                PingChart(samples: ping.samples, maximum: ping.maxMilliseconds)
                if ping.samples.contains(where: { $0.microseconds == nil }) {
                    Label("Timed Out", systemImage: "xmark").font(.caption).foregroundStyle(.orange)
                }
                if let average = ping.averageMicros { LabeledContent("Average RTT", value: DevicePing.milliseconds(average)) }
                if let setup = ping.setupMicros { LabeledContent("Connection Setup", value: DevicePing.milliseconds(Double(setup))) }
                LabeledContent("Measured") { Text(latest.date, style: .time) }
            } else if ping.isRunning {
                HStack { ProgressView(); Text("Testing connection…").foregroundStyle(.secondary) }
            } else if ping.error == nil {
                Text("No measurements yet").foregroundStyle(.secondary)
            }
            if let error = ping.error { Text(verbatim: error).foregroundStyle(.red).textSelection(.enabled) }
        } header: {
            HStack {
                Text("Ping")
                Spacer()
                Button { if ping.isRunning { ping.stop() } else { start() } } label: {
                    Label(ping.isRunning ? "Stop Ping" : "Start Ping", systemImage: ping.isRunning ? "stop.fill" : "play.fill").labelStyle(.iconOnly)
                }
                .frame(minWidth: 44, minHeight: 44)
                .disabled(!ping.isRunning && !canPing)
                .accessibilityIdentifier("memberPing")
            }.textCase(nil)
        } footer: {
            Text("Measures encrypted round trips to this device through the relay. Connection setup is measured separately. No card or PIN is requested.")
        }
    }
}
