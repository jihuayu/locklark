import SwiftUI
import LocklarkSecurityLogic

@main
@MainActor
struct LocklarkApp: App {
    @StateObject private var model = VaultModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .tint(.blue)
                .overlay {
                    if model.covered {
                        Color(uiColor: .systemBackground).ignoresSafeArea()
                            .overlay {
                                VStack(spacing: 16) {
                                    Image(systemName: "lock.shield.fill")
                                        .font(.system(size: 44, weight: .semibold))
                                        .foregroundStyle(.blue)
                                        .accessibilityHidden(true)
                                    Label("Locklark 已锁定", systemImage: "lock.fill")
                                        .font(.title2.weight(.semibold))
                                    Text("已启用后台隐私保护，敏感凭据已从界面隐藏")
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                        .multilineTextAlignment(.center)
                                        .padding(.horizontal, 28)
                                    if model.systemUnlockPending {
                                        Button("取消系统验证", role: .cancel) { model.cancelSystemAuthentication() }
                                            .buttonStyle(.borderedProminent)
                                            .tint(.secondary)
                                            .accessibilityIdentifier("cancel-system-auth")
                                    }
                                }
                                .padding(24)
                            }
                            .accessibilityIdentifier("privacy-cover")
                    }
                }
                .onChange(of: scenePhase, initial: true) { _, phase in
                    switch phase {
                    case .active: model.sceneActive()
                    case .inactive: model.sceneInactive()
                    case .background: model.sceneBackground()
                    @unknown default: model.sceneBackground()
                    }
                }
        }
    }
}

@MainActor
private struct RootView: View {
    @EnvironmentObject private var model: VaultModel

    private var isWarningStatus: Bool {
        let text = model.status
        return text.contains("无法") || text.contains("失败") || text.contains("无效") ||
            text.contains("不可") || text.contains("拒绝") || text.contains("未完成") || text.contains("已过期")
    }

    var body: some View {
        NavigationStack {
            Group {
                if model.unlocked { vault }
                else if model.creatingVault && !model.hasVault { createVault }
                else { unlock }
            }
            .navigationTitle("Locklark")
            .toolbar {
                if model.unlocked {
                    Button("锁定", systemImage: "lock.fill") { model.lock() }
                        .tint(.red)
                        .accessibilityIdentifier("lock-vault")
                }
            }
            .safeAreaInset(edge: .bottom) {
                if !model.status.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: isWarningStatus ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                            .foregroundStyle(isWarningStatus ? .red : .blue)
                            .accessibilityHidden(true)
                        Text(verbatim: model.status)
                            .font(.footnote.weight(.medium))
                            .foregroundStyle(isWarningStatus ? .red : .primary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityIdentifier("vault-status")
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(.ultraThinMaterial)
                    .overlay(alignment: .top) { Divider() }
                }
            }
            .sheet(isPresented: $model.creatingLogin, onDismiss: { model.cancelEditor() }) { loginEditor }
            .sheet(isPresented: Binding(get: { model.editingField != nil }, set: { if !$0 { model.cancelEditor() } })) { fieldEditor }
        }
    }

    private var unlock: some View {
        Form {
            Section {
                Label("本机零知识离线金库", systemImage: "lock.shield.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.blue)
                Text("主密码与 Secret Key 仅在当前原生安全窗口内参与解密，绝不存储为快速解锁凭据。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if model.hasVault {
                Section("双因素完整解锁") {
                    SecureField("主密码", text: $model.password)
                        .textContentType(.password)
                        .accessibilityIdentifier("unlock-password")
                    SecureField("账户 Secret Key", text: $model.secretKey)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("unlock-secret-key")
                    Button("解锁金库", systemImage: "key.fill") { model.unlockWithFactors() }
                        .font(.body.weight(.semibold))
                        .accessibilityIdentifier("unlock-vault")
                        .disabled(!model.ready || model.interactionBusy || model.password.isEmpty || model.secretKey.isEmpty)
                }
                Section("设备快速验证") {
                    Button("使用系统验证解锁", systemImage: "faceid") { model.unlockWithSystem() }
                        .accessibilityIdentifier("system-unlock")
                        .disabled(!model.ready || model.interactionBusy)
                    Text("仅在事先启用本机快速解锁后可用。若系统验证取消或超时，请使用完整双因素解锁。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                Section("初始化金库") {
                    Button("创建个人金库", systemImage: "plus.circle.fill") { model.creatingVault = true }
                        .font(.body.weight(.semibold))
                        .accessibilityIdentifier("create-vault")
                        .disabled(!model.ready || model.interactionBusy)
                }
            }
            if model.interactionBusy { ProgressView("正在验证安全凭据…") }
        }
        .accessibilityIdentifier("locked-screen")
    }

    private var createVault: some View {
        Form {
            Section("1. 设置主密码") {
                SecureField("主密码", text: $model.password)
                    .textContentType(.newPassword)
                    .accessibilityIdentifier("create-password")
                SecureField("再次输入", text: $model.confirmation)
                    .textContentType(.newPassword)
                    .accessibilityIdentifier("create-confirmation")
            }
            Section("2. 账户 Secret Key") {
                Button("生成新的 Secret Key", systemImage: "key.horizontal.fill") { model.generateAccountKey() }
                    .accessibilityIdentifier("generate-secret-key")
                    .disabled(model.interactionBusy)
                if !model.generatedSecretKey.isEmpty {
                    Text(verbatim: model.generatedSecretKey)
                        .font(.system(.callout, design: .monospaced).weight(.semibold))
                        .padding(.vertical, 4)
                        .privacySensitive()
                        .accessibilityLabel("账户 Secret Key")
                        .accessibilityValue(model.generatedSecretKey)
                        .accessibilityIdentifier("create-secret-key")
                    Text("请将此密钥抄录或保存在本机之外的安全位置。一旦遗失主密码或 Secret Key，设备快速解锁无法替代恢复。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Toggle("我已在此设备之外安全保存 Secret Key", isOn: $model.backupAcknowledged)
                        .accessibilityIdentifier("backup-ack")
                }
            }
            Button("确认备份并创建", systemImage: "checkmark.shield.fill") { model.createVault() }
                .font(.body.weight(.semibold))
                .accessibilityIdentifier("confirm-create")
                .disabled(model.interactionBusy || model.password.isEmpty || model.password != model.confirmation || !model.backupAcknowledged)
            Button("取消", role: .cancel) { model.lock(); model.creatingVault = false }
        }
        .navigationTitle("创建金库")
    }

    private var vault: some View {
        List {
            Section {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    TextField("仅搜索标题", text: $model.query)
                        .submitLabel(.search)
                        .onSubmit { model.search() }
                        .accessibilityIdentifier("title-search")
                    Button("搜索") { model.search() }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("search-submit")
                }
                Button("添加登录", systemImage: "plus.circle.fill") { model.beginAdd() }
                    .font(.body.weight(.medium))
                    .accessibilityIdentifier("add-login")
                    .disabled(model.interactionBusy)
            }
            if let selected = model.selected {
                Section("当前选中凭据") {
                    Text(verbatim: VisibleText.title(selected.title))
                        .font(.headline)
                    Text("固定条目 \(selected.identifier)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Text("修订 \(selected.revision)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                    ForEach([
                        ("username", "显示用户名", "person.text.rectangle"),
                        ("password", "显示密码", "key.horizontal"),
                        ("notes", "显示备注", "note.text"),
                        ("otp-code", "显示验证码", "clock.badge.checkmark")
                    ], id: \.0) { field, title, icon in
                        Button(title, systemImage: icon) { model.reveal(field: field) }
                            .accessibilityIdentifier("show-\(field)")
                            .disabled(model.interactionBusy)
                    }
                    if model.hasDisclosure {
                        Text(verbatim: model.revealed.isEmpty ? "（空值）" : model.revealed)
                            .font(.system(.body, design: .monospaced).weight(.medium))
                            .padding(.vertical, 4)
                            .privacySensitive()
                            .accessibilityLabel("本次显示值")
                            .accessibilityValue(model.revealed)
                            .accessibilityIdentifier("revealed-value")
                        Button("隐藏", systemImage: "eye.slash", role: .destructive) { model.clearDisclosure() }
                            .accessibilityIdentifier("hide-value")
                    }
                    Menu("编辑字段", systemImage: "pencil.line") {
                        ForEach([
                            ("title", "标题"),
                            ("url", "网址"),
                            ("username", "用户名"),
                            ("password", "密码"),
                            ("otp", "验证码配置"),
                            ("notes", "备注")
                        ], id: \.0) { field, title in
                            Button(title) { model.beginEdit(field: field) }
                                .accessibilityIdentifier("edit-\(field)")
                        }
                    }
                    .accessibilityIdentifier("edit-fields")
                    .disabled(model.interactionBusy)
                    Button("重新生成 24 位密码", systemImage: "arrow.triangle.2.circlepath") { model.regenerate() }
                        .accessibilityIdentifier("regenerate-password")
                        .disabled(model.interactionBusy)
                    Button("取消选择", role: .cancel) { model.select(nil) }
                        .disabled(model.interactionBusy)
                }
            }
            Section("登录凭据 (\(model.rows.count))") {
                if model.rows.isEmpty {
                    Text(model.query.isEmpty ? "暂无保存的登录凭据，点击上方「添加登录」创建。" : "未找到匹配的登录标题。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                ForEach(model.rows, id: \.identifier) { row in
                    Button { model.select(row) } label: {
                        Text(verbatim: VisibleText.title(row.title))
                            .font(.body.weight(model.selected?.identifier == row.identifier ? .semibold : .regular))
                    }
                    .accessibilityIdentifier("row-title-\(VisibleText.title(row.title))")
                }
            }
            Section("此设备安全授权") {
                Button("启用本机快速解锁", systemImage: "faceid") { model.configureQuickUnlock(enable: true) }
                    .accessibilityIdentifier("enable-system-unlock")
                    .disabled(model.interactionBusy)
                Button("移除本机快速解锁", systemImage: "lock.slash", role: .destructive) { model.configureQuickUnlock(enable: false) }
                    .disabled(model.interactionBusy)
                Text("默认关闭。启用后仅将受保护胶囊保存在需本机生物识别/锁屏验证、不可迁移且不参与云同步的系统钥匙串中。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityIdentifier("vault-list")
    }

    private var loginEditor: some View {
        NavigationStack {
            Form {
                Section("基本资料") {
                    TextField("标题", text: $model.titleDraft)
                        .accessibilityIdentifier("login-title")
                    TextField("HTTPS 网址（可选）", text: $model.urlDraft)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("login-url")
                }
                Section("登录凭据") {
                    SecureField("用户名", text: $model.usernameDraft)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("login-username")
                    Toggle("生成 24 位密码", isOn: $model.generatePassword)
                        .accessibilityIdentifier("login-generate")
                    if !model.generatePassword {
                        SecureField("密码", text: $model.passwordDraft)
                            .accessibilityIdentifier("login-password")
                    }
                }
            }
            .navigationTitle("添加登录")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { model.cancelEditor() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { model.saveLogin() }
                        .fontWeight(.semibold)
                        .accessibilityIdentifier("save-login")
                        .disabled(model.interactionBusy || model.titleDraft.isEmpty || (!model.generatePassword && model.passwordDraft.isEmpty))
                }
            }
        }
    }

    private var fieldEditor: some View {
        NavigationStack {
            Form {
                Section("安全编辑说明") {
                    Text("编辑从空白开始输入。保存将更新目标条目的对应字段；取消不会写入任何更改。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    if let row = model.selected {
                        Text("条目 \(row.identifier)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text("修订 \(row.revision)")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                Section("输入新值") {
                    if model.editingField == "notes" {
                        TextEditor(text: $model.editDraft)
                            .frame(minHeight: 180)
                            .privacySensitive()
                            .accessibilityIdentifier("edit-value")
                    } else {
                        SecureField("新值", text: $model.editDraft)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityIdentifier("edit-value")
                    }
                }
            }
            .navigationTitle("编辑字段")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { model.cancelEditor() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { model.saveEdit() }
                        .fontWeight(.semibold)
                        .accessibilityIdentifier("save-edit")
                }
            }
        }
    }
}
