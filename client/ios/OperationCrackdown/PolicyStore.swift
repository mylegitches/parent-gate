import Foundation
import UIKit

@MainActor
final class PolicyStore: ObservableObject {
    @Published var policy: ClientPolicy?
    @Published var status = "Not enrolled"
    @Published var enrolled = false
    @Published var server = UserDefaults.standard.string(forKey: "serverUrl") ?? ""
    @Published var deviceName = UIDevice.current.name
    @Published var enrollmentCode = ""
    @Published var pin = ""
    @Published var durationMinutes = 60

    let controls = FamilyControlsManager()
    private var credential: String? { KeychainStore.read(account: "deviceCredential") }

    func start() async {
        enrolled = credential != nil && !server.isEmpty
        if enrolled { await synchronize() }
    }

    func enroll() async {
        do {
            status = "Enrolling…"
            let response = try await ApiClient.shared.enroll(server: server, code: enrollmentCode, name: deviceName)
            try KeychainStore.save(response.credential, account: "deviceCredential")
            server = response.serverUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            UserDefaults.standard.set(server, forKey: "serverUrl")
            enrolled = true
            try await controls.authorize()
            await synchronize()
        } catch { status = "Enrollment failed: \(error.localizedDescription)" }
    }

    func synchronize() async {
        guard let credential else { return }
        do {
            let latest = try await ApiClient.shared.policy(server: server, credential: credential)
            policy = latest
            controls.apply(latest)
            try await ApiClient.shared.targets(server: server, credential: credential, serviceKeys: controls.configuredKeys())
            status = "Confirmed revision \(latest.revision)"
        } catch { status = "Waiting to synchronize: \(error.localizedDescription)" }
    }

    func override(targetType: String, targetId: String, action: String) async {
        guard let credential, let policy,
              let parentKey = PinVerifierUtil.parentKey(for: pin, in: policy) else {
            status = "Incorrect parent PIN."
            return
        }
        let expiration = durationMinutes > 0
            ? ISO8601DateFormatter().string(from: Date().addingTimeInterval(Double(durationMinutes * 60)))
            : nil
        let operation = LocalOperation(
            operationId: UUID().uuidString.lowercased(),
            deviceId: policy.deviceId,
            baseRevision: policy.revision,
            parentKeyId: parentKey,
            targetType: targetType,
            targetId: targetId,
            action: action,
            effectiveUntil: expiration,
            createdAt: ISO8601DateFormatter().string(from: Date())
        )
        do {
            let response = try await ApiClient.shared.localOperation(server: server, credential: credential, operation: operation)
            self.policy = response.policy
            controls.apply(response.policy)
            pin = ""
            status = "Local override synchronized."
        } catch { status = "Override could not synchronize: \(error.localizedDescription)" }
    }
}
