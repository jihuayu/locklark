import AppKit
import Combine
import SwiftUI

@main
struct LocklarkSafariApp: App {
    @StateObject private var coordinator = RelayCoordinator()

    var body: some Scene {
        WindowGroup("Locklark") {
            RelayStatusView(coordinator: coordinator)
                .task { coordinator.start() }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

struct RelayStatusView: View {
    @ObservedObject var coordinator: RelayCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Locklark for Safari")
                .font(.title2)
            Text(coordinator.status)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text(
                "The Safari extension connects through this app. Keep the app running while you use the extension. The native vault stays in the embedded helper."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(minWidth: 460, minHeight: 220, alignment: .topLeading)
    }
}

@MainActor
final class RelayCoordinator: ObservableObject {
    @Published private(set) var status = "Native relay not started"
    private var server: RelayServer?

    func start() {
        guard server == nil else { return }
        do {
            let identity = try ConfiguredIdentity.from(bundle: .main)
            try identity.validateRuntimeBundles(
                actualExtensionBundleID: identity.extensionBundleID,
                actualContainingAppBundleID: Bundle.main.bundleIdentifier
            )
            let server = try RelayServer(identity: identity)
            server.onStatusChange = { [weak self] text in
                DispatchQueue.main.async {
                    self?.status = text
                }
            }
            try server.start()
            self.server = server
            status = "Native relay ready"
        } catch {
            // Fixed text only: never surface paths, identities or raw errors.
            status = "Unavailable: signed app identity or app group is missing"
            server = nil
        }
    }

    func stop() {
        server?.stop()
        server = nil
        status = "Native relay stopped"
    }
}
