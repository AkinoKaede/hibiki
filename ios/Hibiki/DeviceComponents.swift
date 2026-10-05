import SwiftUI

struct DeviceStatus: View {
    let online: Bool
    let available: Bool
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(available && online ? Color.green : Color.secondary)
                .frame(width: 8, height: 8).accessibilityHidden(true)
            Text(available ? (online ? "Online" : "Offline") : "Status Unavailable")
        }
        .foregroundStyle(available && online ? Color.green : Color.secondary)
        .accessibilityElement(children: .combine)
    }
}

struct VerificationWords: View {
    let words: String
    var body: some View {
        let values = words.split(whereSeparator: { $0.isWhitespace })
        ForEach(0..<((values.count + 5) / 6), id: \.self) { row in
            Text(verbatim: values.dropFirst(row * 6).prefix(6).joined(separator: " "))
                .font(.system(.body, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }
}
