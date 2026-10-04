import Foundation
import UIKit
import UserNotifications

@MainActor
final class PolicyStore: ObservableObject {
    @Published var policy: ClientPolicy?
    @Published var status = "Not enrolled"
    @Published var enrolled = false
    @Published var server = UserDefaults.standard.string(forKey: "serverUrl") ?? ""
    @Published var deviceName = UIDevice.current.name
    @Published var enrollmentCode = ""
    @Published var pin = ""
    @Published var durationMinutes = 0

    let controls = FamilyControlsManager()
    private var credential: String? { KeychainStore.read(account: "deviceCredential") }

    func start() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
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
            updateInternetNotice(latest)
            try await ApiClient.shared.targets(server: server, credential: credential, serviceKeys: controls.configuredKeys())
            status = "Confirmed revision \(latest.revision)"
        } catch { status = "Waiting to synchronize: \(error.localizedDescription)" }
    }

    private func updateInternetNotice(_ policy: ClientPolicy) {
        let center = UNUserNotificationCenter.current()
        guard policy.internetBlocked == true else {
            center.removeDeliveredNotifications(withIdentifiers: ["parentgate-internet"])
            UserDefaults.standard.removeObject(forKey: "lastInternetNoticeId")
            return
        }
        let noticeId = policy.internetNoticeId ?? "internet-paused"
        guard UserDefaults.standard.string(forKey: "lastInternetNoticeId") != noticeId else { return }
        UserDefaults.standard.set(noticeId, forKey: "lastInternetNoticeId")
        let content = UNMutableNotificationContent()
        content.title = "Internet access is paused"
        content.body = policy.internetMessage ?? "Internet access is paused."
        content.sound = .default
        center.add(UNNotificationRequest(identifier: "parentgate-internet", content: content, trigger: nil))
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
