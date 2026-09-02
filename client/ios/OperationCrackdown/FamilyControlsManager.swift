import DeviceActivity
import FamilyControls
import Foundation
import ManagedSettings

@MainActor
final class FamilyControlsManager: ObservableObject {
    @Published var selection = FamilyActivitySelection()
    @Published var selectionKey = "discord"
    private let store = ManagedSettingsStore(named: .init("OperationCrackdown"))
    private let defaults = UserDefaults(suiteName: "group.com.operationcrackdown.client")!

    func authorize() async throws {
        try await AuthorizationCenter.shared.requestAuthorization(for: .child)
    }

    func saveCurrentSelection() throws {
        let data = try PropertyListEncoder().encode(selection)
        defaults.set(data, forKey: "selection.\(selectionKey)")
    }

    func configuredKeys() -> [String] {
        [
            "discord", "snapchat", "facebook", "instagram", "whatsapp", "telegram",
            "signal", "slack", "teams", "google-chat", "google-messages", "zoom", "reddit", "tiktok",
            "x-twitter", "roblox", "netflix", "paramount", "discovery", "hulu", "youtube"
        ].filter {
            defaults.data(forKey: "selection.\($0)") != nil
        }
    }

    func apply(_ policy: ClientPolicy) {
        var applications = Set<ApplicationToken>()
        var webDomains = Set<WebDomainToken>()
        for service in policy.services where service.blocked {
            guard let key = service.ios?.localSelectionKey,
                  let data = defaults.data(forKey: "selection.\(key)"),
                  let selected = try? PropertyListDecoder().decode(FamilyActivitySelection.self, from: data) else { continue }
            applications.formUnion(selected.applicationTokens)
            webDomains.formUnion(selected.webDomainTokens)
        }
        store.shield.applications = applications.isEmpty ? nil : applications
        store.shield.webDomains = webDomains.isEmpty ? nil : webDomains
    }
}
