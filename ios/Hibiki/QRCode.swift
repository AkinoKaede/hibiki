import SwiftUI
import PhotosUI
import Vision
import CoreImage.CIFilterBuiltins
@preconcurrency import AVFoundation

enum PairingQR {
    static func image(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let padded = output.extent.insetBy(dx: -4, dy: -4)
        let white = CIImage(color: CIColor.white).cropped(to: padded)
        let rendered = output.composited(over: white).transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        guard let image = CIContext().createCGImage(rendered, from: rendered.extent) else { return nil }
        return UIImage(cgImage: image)
    }
    static func read(_ data: Data) throws -> [String] {
        let request = VNDetectBarcodesRequest()
        #if targetEnvironment(simulator)
        // The simulator lacks the inference models used by newer revisions.
        // Revision 1 detects the same QR payloads with the legacy CPU decoder.
        request.revision = 1
        for (stage, devices) in try request.supportedComputeStageDevices {
            if let cpu = devices.first(where: { if case .cpu = $0 { return true }; return false }) {
                request.setComputeDevice(cpu, for: stage)
            }
        }
        #endif
        request.symbologies = [.qr]
        try VNImageRequestHandler(data: data).perform([request])
        return Array(Set((request.results ?? []).compactMap(\.payloadStringValue))).sorted()
    }
}

struct PairingQRCode: View {
    let text: String
    var body: some View {
        if let image = PairingQR.image(text) {
            Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
                .frame(maxWidth: 360).accessibilityLabel("Pairing QR Code")
                .accessibilityIdentifier("pairingQRCode")
        } else { Text("Unable to generate QR code.") }
    }
}

struct QRShareSheet: UIViewControllerRepresentable {
    let text: String
    func makeUIViewController(context: Context) -> UIActivityViewController {
        var items: [Any] = [text]
        if let image = PairingQR.image(text) { items.append(image) }
        return UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

struct QRScannerSheet: View {
    enum Purpose {
        case invitation, verification
        var prefix: String { self == .invitation ? "hibiki-invite-v2:" : "hibiki-verify-v1:" }
    }
    let purpose: Purpose
    var describeError: (Error) -> String = { $0.localizedDescription }
    let recognized: (String) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var photo: PhotosPickerItem?
    @State private var processing = false
    @State private var error: String?
    @State private var candidates: [String] = []
    @State private var work: Task<Void, Never>?
    @State private var visible = true
    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                QRScannerCamera(active: !processing && candidates.isEmpty && visible && scenePhase == .active, recognized: handle, failed: { error = $0 })
                    .clipShape(RoundedRectangle(cornerRadius: 16)).frame(maxHeight: 420)
                Text(purpose == .invitation ? LocalizedStringKey("Scan a one-use invitation to request admission.") : LocalizedStringKey("A matching verification code will approve this request immediately."))
                    .font(.callout).foregroundStyle(.secondary)
                if processing && error == nil { ProgressView() }
                if let error { Text(verbatim: error).foregroundStyle(.red) }
                if error != nil {
                    Button("Try Again") { error = nil; processing = false; candidates = [] }
                }
                ForEach(candidates, id: \.self) { candidate in
                    Button { handle(candidate) } label: {
                        Text(verbatim: candidate).lineLimit(2).font(.caption.monospaced())
                    }
                }
                PhotosPicker(selection: $photo, matching: .images) {
                    Label("Choose QR Image", systemImage: "photo")
                }.disabled(processing && error == nil).accessibilityIdentifier("chooseQRImage")
                Spacer(minLength: 0)
            }.padding()
                .navigationTitle(purpose == .invitation ? String(localized: "Scan Invitation") : String(localized: "Scan and Approve"))
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { stop(); dismiss() } } }
                .onChange(of: photo) { _, item in
                    guard let item else { return }
                    work?.cancel(); processing = true; error = nil; candidates = []
                    work = Task { @MainActor in
                        do {
                            guard let data = try await item.loadTransferable(type: Data.self) else { throw QRReadError.noCode }
                            let codes = try await Task.detached { try PairingQR.read(data) }.value
                            try Task.checkCancellation()
                            guard visible else { return }
                            let matching = codes.filter { $0.hasPrefix(purpose.prefix) }
                            guard !matching.isEmpty else { throw QRReadError.noCode }
                            processing = false
                            if matching.count == 1 { handle(matching[0]) } else { candidates = matching }
                        } catch is CancellationError { } catch { self.error = describeError(error) }
                        photo = nil
                    }
                }
                .onChange(of: scenePhase) { _, phase in if phase == .background { stop(); dismiss() } }
                .onDisappear { stop() }
        }
    }
    private func handle(_ value: String) {
        guard visible, !processing, scenePhase == .active else { return }
        processing = true; error = nil; candidates = []
        work = Task { @MainActor in
            do {
                guard value.hasPrefix(purpose.prefix) else { throw QRReadError.wrongType }
                try Task.checkCancellation()
                guard visible else { return }
                try await recognized(value)
                try Task.checkCancellation()
                dismiss()
            } catch is CancellationError { } catch { self.error = describeError(error) }
        }
    }
    private func stop() { visible = false; work?.cancel(); work = nil }
}
private enum QRReadError: LocalizedError {
    case noCode, wrongType
    var errorDescription: String? {
        switch self {
        case .noCode: String(localized: "No matching QR code found in this image.")
        case .wrongType: String(localized: "This QR code is for a different pairing step.")
        }
    }
}

private struct QRScannerCamera: UIViewControllerRepresentable {
    let active: Bool
    let recognized: (String) -> Void
    let failed: (String) -> Void
    func makeUIViewController(context: Context) -> CameraController {
        let controller = CameraController()
        controller.recognized = recognized; controller.failed = failed
        return controller
    }
    func updateUIViewController(_ controller: CameraController, context: Context) { controller.setActive(active) }
    static func dismantleUIViewController(_ controller: CameraController, coordinator: ()) { controller.setActive(false) }
}
private final class CameraController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var recognized: ((String) -> Void)?
    var failed: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "hibiki.qr-camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var active = false
    private var configured = false
    private var requesting = false
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview); self.preview = preview
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    func setActive(_ value: Bool) {
        guard value != active else { return }
        active = value
        guard value else { let session = session; queue.async { session.stopRunning() }; return }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: start()
        case .notDetermined:
            guard !requesting else { return }; requesting = true
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                Task { @MainActor in
                    guard let self else { return }; self.requesting = false
                    guard self.active else { return }
                    if granted { self.start() } else { self.failed?(String(localized: "Camera access is unavailable. Choose a QR image instead.")) }
                }
            }
        default: failed?(String(localized: "Camera access is unavailable. Choose a QR image instead."))
        }
    }
    private func start() {
        guard active else { return }
        if !configured {
            guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else {
                failed?(String(localized: "Camera access is unavailable. Choose a QR image instead.")); return
            }
            session.beginConfiguration(); session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { session.commitConfiguration(); return }
            session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
            session.commitConfiguration(); configured = true
        }
        let session = session
        queue.async { if !session.isRunning { session.startRunning() } }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard active, let value = metadataObjects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first else { return }
        recognized?(value)
    }
}
