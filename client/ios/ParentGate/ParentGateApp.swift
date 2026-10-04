import SwiftUI

@main
struct ParentGateApp: App {
    @StateObject private var store = PolicyStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                .task { await store.start() }
        }
    }
}

