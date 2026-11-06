import Foundation
import SwiftUI
import LocklarkSecurityLogic

@MainActor
final class VaultModel: ObservableObject {
    @Published private(set) var ready = false
    @Published private(set) var hasVault = false
    @Published private(set) var unlocked = false
    @Published private(set) var covered = false
    @Published private(set) var busy = false
    @Published private(set) var rows: [LLRow] = []
    @Published private(set) var selected: LLRow?
    @Published private(set) var revealed = ""
    @Published var status = ""
    @Published var query = ""
    @Published var password = ""
    @Published var confirmation = ""
    @Published var secretKey = ""
    @Published var generatedSecretKey = ""
    @Published var backupAcknowledged = false
    @Published var creatingVault = false
    @Published var creatingLogin = false
    @Published var editingField: String?
    @Published var titleDraft = ""
    @Published var urlDraft = ""
    @Published var usernameDraft = ""
    @Published var passwordDraft = ""
    @Published var editDraft = ""
    @Published var generatePassword = false

    private let worker = DispatchQueue(label: "org.locklark.mobile.vault", qos: .userInitiated)
    private let systemStore = NativeSystemUnlockStore()
    private var activeAuthentication: NativeSystemUnlockStore?
    private var boundary = SessionBoundary()
    private var operation = OperationBoundary()
    private var vault: LLVault?
    private var databaseURL: URL?
    private var disclosure: LLDisclosure?
    private var budget: DisclosureBudget?
    private var shownAt: ContinuousClock.Instant?
    private var expiryTask: Task<Void, Never>?
    private var idleTask: Task<Void, Never>?

    init() {
        worker.async { [weak self] in
            do {
                let url = try VaultFiles.prepare()
                let exists = FileManager.default.fileExists(atPath: url.path)
                let handle = try LLVault.open(path: url.path)
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.databaseURL = url
                    self.vault = handle
                    self.hasVault = exists
                    self.ready = true
                    if !self.boundary.isActive { handle.requestLock() }
                }
            } catch {
                DispatchQueue.main.async { self?.status = "无法启用本机受保护存储。" }
            }
        }
        idleTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                if self.unlocked, self.vault?.isUnlocked() != true { self.lock() }
            }
        }
    }

    private func perform<T>(_ action: @escaping (LLVault) throws -> T, completion: @escaping (Result<T, Error>) -> Void) {
        guard let vault else { status = "金库尚未准备好。"; return }
        worker.async {
            let result: Result<T, Error> = autoreleasepool { Result { try action(vault) } }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func sceneInactive() {
        covered = true
        boundary.resignActive()
        invalidateUI()
        vault?.requestLock()
        systemStore.keychain.cancelAuthentication()
        activeAuthentication?.keychain.cancelAuthentication()
        activeAuthentication = nil
        if let vault { worker.async { vault.lock() } }
    }

    func sceneActive() {
        boundary.becomeActive()
        covered = false
        // Returning from a system prompt never automatically retries unlock.
    }

    func lock() {
        boundary.lock()
        invalidateUI()
        vault?.requestLock()
        systemStore.keychain.cancelAuthentication()
        activeAuthentication?.keychain.cancelAuthentication()
        activeAuthentication = nil
        if let vault { worker.async { vault.lock() } }
    }

    private func invalidateUI() {
        unlocked = false
        cancelOperation()
        rows = []
        selected = nil
        query = ""
        creatingLogin = false
        editingField = nil
        clearDisclosure()
        clearDrafts()
        password = ""
        confirmation = ""
        secretKey = ""
        generatedSecretKey = ""
        backupAcknowledged = false
        status = "已锁定。"
    }

    func clearDisclosure() {
        expiryTask?.cancel()
        expiryTask = nil
        disclosure?.clear() // Only a local NSMutableData buffer; no Go/disk call.
        disclosure = nil
        budget = nil
        shownAt = nil
        revealed = ""
    }

    private func clearDrafts() {
        titleDraft = ""
        urlDraft = ""
        usernameDraft = ""
        passwordDraft = ""
        editDraft = ""
        generatePassword = false
    }

    private func beginOperation() -> OperationToken {
        let token = operation.begin()
        busy = operation.isBusy
        return token
    }

    @discardableResult
    private func finishOperation(_ token: OperationToken) -> Bool {
        guard operation.finish(token) else { return false }
        busy = operation.isBusy
        return true
    }

    private func cancelOperation() {
        operation.cancel()
        busy = operation.isBusy
    }

    func generateAccountKey() {
        guard ready, !busy, boundary.isActive else { return }
        do {
            var key = try LLVault.generateSecretKey()
            defer { key.resetBytes(in: 0..<key.count) }
            generatedSecretKey = LLVault.formatSecretKey(key)
            backupAcknowledged = false
        } catch { status = "无法生成 Secret Key。" }
    }

    func createVault() {
        guard !hasVault, !busy, backupAcknowledged, !generatedSecretKey.isEmpty,
              !password.isEmpty, password == confirmation,
              let attempt = boundary.beginUnlock(), let url = databaseURL else { return }
        do {
            var passwordData = Data(password.utf8)
            var key = try LLVault.parseSecretKey(generatedSecretKey)
            password = ""; confirmation = ""; generatedSecretKey = ""; backupAcknowledged = false
            let owner = beginOperation()
            perform({ vault in
                defer { passwordData.resetBytes(in: 0..<passwordData.count); key.resetBytes(in: 0..<key.count) }
                try vault.create(password: passwordData, secretKey: key)
                try VaultFiles.verifyProtection(directory: url.deletingLastPathComponent())
                try VaultFiles.protect(directory: url.deletingLastPathComponent())
            }, completion: { [weak self] result in
                guard let self else { return }
                self.hasVault = FileManager.default.fileExists(atPath: url.path)
                guard self.finishOperation(owner), self.boundary.finishUnlock(attempt) else { return }
                self.boundary.lock()
                self.unlocked = false
                self.creatingVault = false
                switch result {
                case .success: self.status = "已创建加密金库。请使用两个完整因素解锁。"
                case .failure(let error):
                    self.vault?.requestLock()
                    if error is PlatformProtectionError { self.ready = false }
                    self.status = "创建结果未确认，或本机文件保护检查失败；请检查金库后再操作。"
                }
            })
        } catch { lock(); status = "Secret Key 格式无效。" }
    }

    func unlockWithFactors() {
        guard hasVault, !busy, !password.isEmpty, let attempt = boundary.beginUnlock() else { return }
        do {
            var passwordData = Data(password.utf8)
            var key = try LLVault.parseSecretKey(secretKey)
            let directory = databaseURL?.deletingLastPathComponent()
            password = ""; secretKey = ""
            let owner = beginOperation()
            perform({ vault in
                defer { passwordData.resetBytes(in: 0..<passwordData.count); key.resetBytes(in: 0..<key.count) }
                if let directory { try VaultFiles.verifyProtection(directory: directory) }
                try vault.unlock(password: passwordData, secretKey: key)
            }, completion: { [weak self] result in self?.finishUnlock(result, attempt: attempt, owner: owner) })
        } catch { lock(); status = "Secret Key 格式无效。" }
    }

    func unlockWithSystem() {
        guard hasVault, !busy, let attempt = boundary.beginUnlock() else { return }
        let owner = beginOperation()
        let store = NativeSystemUnlockStore()
        activeAuthentication = store
        let directory = databaseURL?.deletingLastPathComponent()
        perform({ vault in
            if let directory { try VaultFiles.verifyProtection(directory: directory) }
            try vault.unlockWithSystem(store)
        }, completion: { [weak self] result in
            self?.finishUnlock(result, attempt: attempt, owner: owner)
        })
    }

    private func finishUnlock(_ result: Result<Void, Error>, attempt: ScreenToken, owner: OperationToken) {
        guard finishOperation(owner), boundary.finishUnlock(attempt) else { return }
        activeAuthentication = nil
        switch result {
        case .success:
            guard vault?.isUnlocked() == true else { lock(); return }
            unlocked = true
            status = ""
            refresh()
        case .failure(let error):
            lock()
            if error is PlatformProtectionError { ready = false }
            status = "无法解锁；系统验证取消或失效时，请使用两个完整因素。"
        }
    }

    func configureQuickUnlock(enable: Bool) {
        guard let token = boundary.capture(), !busy else { return }
        let owner = beginOperation()
        let store = systemStore
        perform({ vault in
            if enable { try vault.enableSystemUnlock(store) } else { try vault.disableSystemUnlock(store) }
        }, completion: { [weak self] result in
            guard let self, self.finishOperation(owner), self.boundary.permits(token) else { return }
            switch result {
            case .success: self.status = enable ? "已启用本机快速解锁，最多至本次完整解锁后 24 小时。" : "已移除本机快速解锁。"
            case .failure: self.status = "系统保护不可用或操作已取消；未使用较弱的存储方式。"
            }
        })
    }

    func search() {
        cancelOperation()
        clearDisclosure()
        clearDrafts()
        selected = nil
        boundary.select(nil)
        refresh()
    }

    func refresh() {
        guard let token = boundary.capture() else { return }
        let owner = beginOperation()
        let text = query
        perform({ try $0.rows(query: text) }, completion: { [weak self] result in
            guard let self, self.finishOperation(owner), self.boundary.permits(token) else { return }
            guard self.vault?.isUnlocked() == true else { self.lock(); return }
            switch result {
            case .success(let rows): self.rows = rows
            case .failure: self.status = "无法读取当前列表。"
            }
        })
    }

    func select(_ row: LLRow?) {
        cancelOperation()
        clearDisclosure()
        clearDrafts()
        selected = row
        editingField = nil
        boundary.select(row.map { VaultTarget(id: $0.identifier, revision: $0.revision, field: "") })
    }

    func reveal(field: String) {
        guard let row = selected, !busy else { return }
        clearDisclosure()
        let target = VaultTarget(id: row.identifier, revision: row.revision, field: field)
        boundary.select(target)
        guard let token = boundary.capture() else { return }
        let owner = beginOperation()
        perform({ try $0.reveal(id: target.id, revision: target.revision, field: target.field) }, completion: { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure:
                guard self.finishOperation(owner), self.boundary.permits(token) else { return }
                self.status = "该值不可显示，可能未配置或条目已改变。"
            case .success(let handle):
                guard self.boundary.permits(token), self.vault?.isUnlocked() == true else {
                    self.finishOperation(owner)
                    self.worker.async { handle.clear() }; return
                }
                self.perform({ _ in defer { handle.clear() }; return try handle.take() }, completion: { [weak self] taken in
                    guard let self else { return }
                    switch taken {
                    case .failure:
                        guard self.finishOperation(owner), self.boundary.permits(token) else { return }
                        self.status = "该值已过期或请求已取消。"
                    case .success(let value):
                        guard self.finishOperation(owner), self.boundary.permits(token), self.selected?.identifier == target.id,
                              self.selected?.revision == target.revision, self.vault?.isUnlocked() == true,
                              let budget = DisclosureBudget(from: value.fromUnixMilli, until: value.untilUnixMilli, issuedWall: Self.wallNow()) else {
                            value.clear(); return
                        }
                        guard let text = String(data: value.data as Data, encoding: .utf8) else { value.clear(); return }
                        self.disclosure = value
                        self.budget = budget
                        self.shownAt = ContinuousClock.now
                        self.revealed = VisibleText.secret(text)
                        self.status = "仅本次显示；验证码不会自动取下一期。"
                        self.expiryTask = Task { [weak self] in
                            while !Task.isCancelled {
                                try? await Task.sleep(for: .milliseconds(100))
                                guard let self, let started = self.shownAt, let budget = self.budget else { return }
                                let elapsed = started.duration(to: .now).components
                                let milliseconds = elapsed.seconds * 1_000 + elapsed.attoseconds / 1_000_000_000_000_000
                                if !self.boundary.permits(token) || self.vault?.isUnlocked() != true ||
                                    !budget.permits(wallNow: Self.wallNow(), elapsedMilliseconds: milliseconds) {
                                    self.clearDisclosure(); return
                                }
                            }
                        }
                    }
                })
            }
        })
    }

    func beginAdd() {
        select(nil)
        creatingLogin = true
    }

    func beginEdit(field: String) {
        guard let row = selected else { return }
        clearDisclosure()
        clearDrafts()
        boundary.select(VaultTarget(id: row.identifier, revision: row.revision, field: field))
        editingField = field
    }

    func cancelEditor() {
        guard creatingLogin || editingField != nil else { return }
        clearDrafts()
        creatingLogin = false
        editingField = nil
        if let row = selected { select(row) }
    }

    func saveLogin() {
        guard creatingLogin, !busy, let token = boundary.capture(), !titleDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let title = titleDraft, url = urlDraft, generate = generatePassword
        var user = Data(usernameDraft.utf8), value = Data(passwordDraft.utf8)
        clearDrafts()
        creatingLogin = false
        mutate(token: token) { vault in
            defer { user.resetBytes(in: 0..<user.count); value.resetBytes(in: 0..<value.count) }
            if generate { return try vault.generateLogin(title: title, url: url, username: user, length: 24) }
            return try vault.createLogin(title: title, url: url, username: user, password: value)
        }
    }

    func saveEdit() {
        guard let row = selected, let field = editingField, !busy, let token = boundary.capture() else { return }
        var value = Data(editDraft.utf8)
        clearDrafts()
        editingField = nil
        mutate(token: token) { vault in
            defer { value.resetBytes(in: 0..<value.count) }
            return try vault.edit(id: row.identifier, revision: row.revision, field: field, value: value)
        }
    }

    func regenerate() {
        guard let row = selected, !busy, let token = boundary.capture() else { return }
        clearDisclosure()
        mutate(token: token) { try $0.regenerate(id: row.identifier, revision: row.revision, length: 24) }
    }

    private func mutate(token: ScreenToken, action: @escaping (LLVault) throws -> LLReceipt) {
        let owner = beginOperation()
        let directory = databaseURL?.deletingLastPathComponent()
        perform({ vault in
            let receipt = try action(vault)
            if let directory { try VaultFiles.verifyProtection(directory: directory); try VaultFiles.protect(directory: directory) }
            return receipt
        }, completion: { [weak self] result in
            guard let self, self.finishOperation(owner), self.boundary.permits(token) else { return }
            switch result {
            case .success:
                self.select(nil)
                self.status = "已保存。显示任何值仍需明确选择。"
                self.refresh()
            case .failure(let error):
                self.vault?.requestLock()
                self.lock()
                if error is PlatformProtectionError { self.ready = false }
                self.status = "操作被拒绝，或结果未确认。请重新解锁检查；不会自动重试或覆盖。"
            }
        })
    }

    private static func wallNow() -> Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }

}
