import FamilyControls
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var store: PolicyStore
    @State private var showPicker = false
    @State private var serviceAction = "block"

    var body: some View {
        NavigationStack {
            Form {
                if store.enrolled { controls } else { enrollment }
                Section { Text(store.status).foregroundStyle(.secondary) }
            }
            .navigationTitle("Operation Crackdown")
        }
    }

    private var enrollment: some View {
        Section("Enroll this device") {
            TextField("Dashboard URL", text: $store.server).textInputAutocapitalization(.never).keyboardType(.URL)
            TextField("Enrollment code", text: $store.enrollmentCode).textInputAutocapitalization(.characters)
            TextField("Device name", text: $store.deviceName)
            Button("Enroll") { Task { await store.enroll() } }
        }
    }

    private var controls: some View {
        Group {
            Section("Local parent override") {
                SecureField("Parent PIN", text: $store.pin).keyboardType(.numberPad)
                Picker("Duration", selection: $store.durationMinutes) {
                    Text("30 minutes").tag(30); Text("1 hour").tag(60); Text("2 hours").tag(120); Text("Until changed").tag(0)
                }
                Button("Normal mode") { Task { await store.override(targetType: "profile", targetId: "normal", action: "set") } }
                Button("Homework mode") { Task { await store.override(targetType: "profile", targetId: "homework", action: "set") } }
                Button("Deep Focus") { Task { await store.override(targetType: "profile", targetId: "deep-focus", action: "set") } }
            }

            if let policy = store.policy {
                Section("Services") {
                    Picker("Action", selection: $serviceAction) { Text("Block").tag("block"); Text("Allow").tag("allow") }
                    ForEach(policy.services) { service in
                        Button("\(service.displayName): \(service.blocked ? "Blocked" : "Allowed")") {
                            Task { await store.override(targetType: "service", targetId: service.id, action: serviceAction) }
                        }
                    }
                }
            }

            Section("Choose apps and websites") {
                Picker("Logical service", selection: Binding(
                    get: { store.controls.selectionKey },
                    set: { store.controls.selectionKey = $0 }
                )) {
                    Text("Discord").tag("discord"); Text("Netflix").tag("netflix"); Text("Paramount+").tag("paramount")
                    Text("discovery+").tag("discovery"); Text("Hulu").tag("hulu"); Text("YouTube").tag("youtube")
                }
                Button("Open Apple activity picker") { showPicker = true }
                    .familyActivityPicker(
                        isPresented: $showPicker,
                        selection: Binding(
                            get: { store.controls.selection },
                            set: { store.controls.selection = $0 }
                        )
                    )
                Button("Save selection") {
                    do { try store.controls.saveCurrentSelection(); Task { await store.synchronize() } }
                    catch { store.status = "Unable to save selection: \(error.localizedDescription)" }
                }
            }
        }
    }
}
