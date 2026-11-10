import AppKit
import Combine
import SwiftUI

@main
struct LocklarkSafariApp: App {
    @StateObject private var coordinator = RelayCoordinator()

    var body: some Scene {
        WindowGroup("Locklark for Safari") {
            RelayStatusView(coordinator: coordinator)
                .task { coordinator.start() }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

enum RelayState: String, Equatable {
    case starting
    case ready
    case stopped
    case unavailable

    var badgeTitle: String {
        switch self {
        case .starting: return "正在启动 · Starting"
        case .ready: return "运行中 · Active"
        case .stopped: return "已停止 · Stopped"
        case .unavailable: return "不可用 · Unavailable"
        }
    }

    var symbolName: String {
        switch self {
        case .starting: return "arrow.triangle.2.circlepath.circle.fill"
        case .ready: return "checkmark.shield.fill"
        case .stopped: return "pause.circle.fill"
        case .unavailable: return "exclamationmark.triangle.fill"
        }
    }

    var tintColor: Color {
        switch self {
        case .starting: return .blue
        case .ready: return .green
        case .stopped: return .orange
        case .unavailable: return .red
        }
    }
}

struct RelayStatusView: View {
    @ObservedObject var coordinator: RelayCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center, spacing: 14) {
                Image(systemName: "lock.shield.fill")
                    .font(.largeTitle.weight(.semibold))
                    .foregroundStyle(.blue)
                    .frame(width: 48, height: 48)
                    .background(Color.blue.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))

                VStack(alignment: .leading, spacing: 4) {
                    Text("Locklark for Safari")
                        .font(.title2.weight(.semibold))
                    Text("本机零知识密码金库 · Safari 扩展安全桥接服务")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                HStack(spacing: 6) {
                    Image(systemName: coordinator.state.symbolName)
                        .foregroundStyle(coordinator.state.tintColor)
                    Text(coordinator.state.badgeTitle)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(coordinator.state.tintColor)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(coordinator.state.tintColor.opacity(0.12))
                .clipShape(Capsule())
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .firstTextBaseline) {
                        Label("桥接通道状态", systemImage: "network.badge.shield.half.filled")
                            .font(.headline)
                        Spacer()
                        HStack(spacing: 8) {
                            if coordinator.state == .ready {
                                Button("停止服务") { coordinator.stop() }
                                    .controlSize(.small)
                            } else {
                                Button("启动服务") { coordinator.start() }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.small)
                            }
                            Button("重新连接") { coordinator.restart() }
                                .controlSize(.small)
                        }
                    }

                    Text(coordinator.status)
                        .font(.callout.monospaced().weight(.medium))
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)

                    Text(coordinator.statusDetail)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(8)
            }

            GroupBox("安全隔离架构") {
                VStack(alignment: .leading, spacing: 8) {
                    securityRow(
                        icon: "checkmark.seal.fill",
                        title: "App Group 代码签名双向核验",
                        detail: "仅接受具备相同开发者团队签名与固定 Bundle ID 的 Safari Web 扩展连接。"
                    )
                    securityRow(
                        icon: "cpu.fill",
                        title: "受限沙箱原生金库辅助进程",
                        detail: "The Safari extension connects through this app. Keep the app running while you use the extension. The native vault stays in the embedded helper."
                    )
                    securityRow(
                        icon: "person.crop.rectangle.stack.fill",
                        title: "Safari 个人资料会话绑定",
                        detail: "基于系统原生 SFExtensionProfileKey 隔离不同浏览个人资料的解锁与填充会话。"
                    )
                }
                .padding(8)
            }

            HStack(spacing: 8) {
                Image(systemName: "safari")
                    .foregroundStyle(.secondary)
                Text("启用方式：打开 Safari 浏览器 → 设置 (⌘,) → 扩展，勾选启用 Locklark 并保持本应用在后台运行。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(24)
        .frame(minWidth: 540, minHeight: 360, alignment: .topLeading)
    }

    private func securityRow(icon: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.subheadline)
                .foregroundStyle(.blue)
                .frame(width: 18, alignment: .center)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

@MainActor
final class RelayCoordinator: ObservableObject {
    @Published private(set) var state: RelayState = .starting
    @Published private(set) var status = "Native relay not started"
    @Published private(set) var statusDetail = "正在准备本机 App Group 安全套接字通道…"
    private var server: RelayServer?

    func start() {
        guard server == nil else { return }
        state = .starting
        do {
            let identity = try ConfiguredIdentity.from(bundle: .main)
            try identity.validateRuntimeBundles(
                actualExtensionBundleID: identity.extensionBundleID,
                actualContainingAppBundleID: Bundle.main.bundleIdentifier
            )
            let server = try RelayServer(identity: identity)
            server.onStatusChange = { [weak self] text in
                DispatchQueue.main.async {
                    self?.applyServerStatus(text)
                }
            }
            try server.start()
            self.server = server
            state = .ready
            status = "Native relay ready"
            statusDetail = "本地加密桥接通道已就绪。请在网页中点击工具栏 Locklark 图标发起显式填充或通行密钥操作。"
        } catch {
            // Fixed text only: never surface paths, identities or raw errors.
            state = .unavailable
            status = "Unavailable: signed app identity or app group is missing"
            statusDetail = "无法建立受保护的 App Group 通道：请使用有效 Apple 开发者团队签名并配置匹配的 App Group 容器。"
            server = nil
        }
    }

    func stop() {
        server?.stop()
        server = nil
        state = .stopped
        status = "Native relay stopped"
        statusDetail = "本地桥接服务已暂停，所有活动扩展会话与辅助进程均已安全关闭。"
    }

    func restart() {
        stop()
        start()
    }

    private func applyServerStatus(_ text: String) {
        status = text
        if text.contains("stopped") {
            state = .stopped
            statusDetail = "本地桥接服务已暂停，所有活动扩展会话与辅助进程均已安全关闭。"
        } else if text.contains("listening") || text.contains("ready") {
            state = .ready
            statusDetail = "本地加密桥接通道已就绪。请在网页中点击工具栏 Locklark 图标发起显式填充或通行密钥操作。"
        }
    }
}
