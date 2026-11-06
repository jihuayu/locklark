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
                .overlay {
                    if model.covered {
                        Color(uiColor: .systemBackground).ignoresSafeArea()
                            .overlay { Label("Locklark 已锁定", systemImage: "lock.fill").font(.title2) }
                            .accessibilityIdentifier("privacy-cover")
                    }
                }
                .onChange(of: scenePhase, initial: true) { _, phase in
                    if phase == .active { model.sceneActive() } else { model.sceneInactive() }
                }
        }
    }
}

@MainActor
private struct RootView: View {
    @EnvironmentObject private var model: VaultModel

    var body: some View {
        NavigationStack {
            Group {
                if model.unlocked { vault }
                else if model.creatingVault && !model.hasVault { createVault }
                else { unlock }
            }
            .navigationTitle("Locklark")
            .toolbar {
                if model.unlocked { Button("锁定", systemImage: "lock") { model.lock() }.accessibilityIdentifier("lock-vault") }
            }
            .safeAreaInset(edge: .bottom) {
                if !model.status.isEmpty {
                    Text(verbatim: model.status).font(.footnote).padding().frame(maxWidth: .infinity)
                        .background(.bar).accessibilityIdentifier("vault-status")
                }
            }
            .sheet(isPresented: $model.creatingLogin, onDismiss: { model.cancelEditor() }) { loginEditor }
            .sheet(isPresented: Binding(get: { model.editingField != nil }, set: { if !$0 { model.cancelEditor() } })) { fieldEditor }
        }
    }

    private var unlock: some View {
        Form {
            Section {
                Label("本机离线金库", systemImage: "lock.shield")
                Text("主密码和 Secret Key 只在原生窗口中使用，不会保存为快速解锁因素。")
            }
            if model.hasVault {
                Section("完整因素解锁") {
                    SecureField("主密码", text: $model.password).textContentType(.password).accessibilityIdentifier("unlock-password")
                    SecureField("账户 Secret Key", text: $model.secretKey).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("unlock-secret-key")
                    Button("解锁金库") { model.unlockWithFactors() }.accessibilityIdentifier("unlock-vault")
                        .disabled(!model.ready || model.busy || model.password.isEmpty || model.secretKey.isEmpty)
                }
                Section {
                    Button("使用系统验证解锁") { model.unlockWithSystem() }.accessibilityIdentifier("system-unlock")
                        .disabled(!model.ready || model.busy)
                    Text("仅在此前明确启用后可用。系统验证被中断时，使用完整因素解锁。")
                        .font(.footnote)
                }
            } else {
                Section {
                    Button("创建个人金库") { model.creatingVault = true }.accessibilityIdentifier("create-vault")
                        .disabled(!model.ready || model.busy)
                }
            }
            if model.busy { ProgressView("正在验证") }
        }
        .accessibilityIdentifier("locked-screen")
    }

    private var createVault: some View {
        Form {
            Section("设置主密码") {
                SecureField("主密码", text: $model.password).textContentType(.newPassword).accessibilityIdentifier("create-password")
                SecureField("再次输入", text: $model.confirmation).textContentType(.newPassword).accessibilityIdentifier("create-confirmation")
            }
            Section("账户 Secret Key") {
                Button("生成新的 Secret Key") { model.generateAccountKey() }.accessibilityIdentifier("generate-secret-key")
                    .disabled(model.busy)
                if !model.generatedSecretKey.isEmpty {
                    Text(verbatim: model.generatedSecretKey).font(.system(.body, design: .monospaced)).privacySensitive()
                        .accessibilityLabel("账户 Secret Key").accessibilityValue(model.generatedSecretKey)
                        .accessibilityIdentifier("create-secret-key")
                    Text("把它安全保存在此设备之外。失去主密码或 Secret Key 后，本机快速解锁不能替代恢复。")
                    Toggle("我已在此设备之外安全保存 Secret Key", isOn: $model.backupAcknowledged).accessibilityIdentifier("backup-ack")
                }
            }
            Button("确认备份并创建") { model.createVault() }.accessibilityIdentifier("confirm-create")
                .disabled(model.busy || model.password.isEmpty || model.password != model.confirmation || !model.backupAcknowledged)
            Button("取消", role: .cancel) { model.lock(); model.creatingVault = false }
        }
        .navigationTitle("创建金库")
    }

    private var vault: some View {
        List {
            Section {
                HStack {
                    TextField("仅搜索标题", text: $model.query).submitLabel(.search).onSubmit { model.search() }
                        .accessibilityIdentifier("title-search")
                    Button("搜索") { model.search() }.accessibilityIdentifier("search-submit")
                }
                Button("添加登录", systemImage: "plus") { model.beginAdd() }.accessibilityIdentifier("add-login").disabled(model.busy)
            }
            if let selected = model.selected {
                Section("已选登录") {
                    Text(verbatim: VisibleText.title(selected.title)).font(.headline)
                    Text("固定条目 \(selected.identifier)").font(.caption).textSelection(.enabled)
                    Text("修订 \(selected.revision)").font(.caption2)
                    ForEach([("username", "显示用户名"), ("password", "显示密码"), ("notes", "显示备注"), ("otp-code", "显示验证码")], id: \.0) { field, title in
                        Button(title) { model.reveal(field: field) }.accessibilityIdentifier("show-\(field)").disabled(model.busy)
                    }
                    if model.hasDisclosure {
                        Text(verbatim: model.revealed.isEmpty ? "（空值）" : model.revealed).font(.system(.body, design: .monospaced)).privacySensitive()
                            .accessibilityLabel("本次显示值").accessibilityValue(model.revealed).accessibilityIdentifier("revealed-value")
                        Button("隐藏") { model.clearDisclosure() }.accessibilityIdentifier("hide-value")
                    }
                    Menu("编辑字段") {
                        ForEach([("title", "标题"), ("url", "网址"), ("username", "用户名"), ("password", "密码"), ("otp", "验证码配置"), ("notes", "备注")], id: \.0) { field, title in
                            Button(title) { model.beginEdit(field: field) }.accessibilityIdentifier("edit-\(field)")
                        }
                    }.accessibilityIdentifier("edit-fields").disabled(model.busy)
                    Button("重新生成 24 位密码") { model.regenerate() }.accessibilityIdentifier("regenerate-password").disabled(model.busy)
                    Button("取消选择") { model.select(nil) }.disabled(model.busy)
                }
            }
            Section("登录") {
                ForEach(model.rows, id: \.identifier) { row in
                    Button { model.select(row) } label: { Text(verbatim: VisibleText.title(row.title)) }
                        .accessibilityIdentifier("row-title-\(VisibleText.title(row.title))")
                }
            }
            Section("此设备") {
                Button("启用本机快速解锁") { model.configureQuickUnlock(enable: true) }.accessibilityIdentifier("enable-system-unlock").disabled(model.busy)
                Button("移除本机快速解锁") { model.configureQuickUnlock(enable: false) }.disabled(model.busy)
                Text("默认关闭。密封身份只保存在需用户验证、不可迁移或云同步的系统钥匙串中。")
                    .font(.footnote)
            }
        }.accessibilityIdentifier("vault-list")
    }

    private var loginEditor: some View {
        NavigationStack {
            Form {
                TextField("标题", text: $model.titleDraft).accessibilityIdentifier("login-title")
                TextField("HTTPS 网址（可选）", text: $model.urlDraft).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("login-url")
                SecureField("用户名", text: $model.usernameDraft).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("login-username")
                Toggle("生成 24 位密码", isOn: $model.generatePassword).accessibilityIdentifier("login-generate")
                if !model.generatePassword { SecureField("密码", text: $model.passwordDraft).accessibilityIdentifier("login-password") }
            }
            .navigationTitle("添加登录")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { model.cancelEditor() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { model.saveLogin() }.accessibilityIdentifier("save-login")
                        .disabled(model.busy || model.titleDraft.isEmpty || (!model.generatePassword && model.passwordDraft.isEmpty))
                }
            }
        }
    }

    private var fieldEditor: some View {
        NavigationStack {
            Form {
                Text("编辑从空白开始。保存会替换固定条目的该字段；取消不会保存。")
                if let row = model.selected {
                    Text("条目 \(row.identifier)").font(.caption)
                    Text("修订 \(row.revision)").font(.caption2)
                }
                if model.editingField == "notes" {
                    TextEditor(text: $model.editDraft).frame(minHeight: 180).privacySensitive().accessibilityIdentifier("edit-value")
                } else {
                    SecureField("新值", text: $model.editDraft).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("edit-value")
                }
            }
            .navigationTitle("编辑字段")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { model.cancelEditor() } }
                ToolbarItem(placement: .confirmationAction) { Button("保存") { model.saveEdit() }.accessibilityIdentifier("save-edit") }
            }
        }
    }
}
