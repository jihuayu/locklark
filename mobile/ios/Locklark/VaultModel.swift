import Foundation
import SwiftUI
import LocalAuthentication
import LocklarkSecurityLogic

@MainActor
final class VaultModel: ObservableObject {
    @Published private(set) var ready = false
    @Published private(set) var hasVault = false
    @Published private(set) var unlocked = false
    @Published private(set) var covered = false
    @Published private(set) var busy = false
    @Published private(set) var settlingLock = false
    @Published private(set) var authenticating = false
    @Published private(set) var systemUnlockPending = false
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
    private var activeAuthentication: NativeSystemUnlockStore?
    private var boundary = SessionBoundary()
    private var operation = OperationBoundary()
    private let cancellation = CancellationScope()
    private var preparingStorage = false
    private var lockCleanup = LockCleanupBoundary()
    private var vault: LLVault?
    private var databaseURL: URL?
    private var disclosure: LLDisclosure?
    private var exposure = ExposureBoundary()
    private var expiryTask: Task<Void, Never>?
    private var idleTask: Task<Void, Never>?
    private var ownedAuthentication = OwnedAuthentication()
    private var authenticationToken: AuthenticationToken?
    private var authenticationContext: LAContext?
    private var authenticationSucceededAt: ContinuousClock.Instant?
    private var authenticationTimeout: Task<Void, Never>?
    private let authenticationCancellation = CancellationScope()
    private let authenticationClockOrigin = ContinuousClock.now
    var hasDisclosure: Bool { disclosure != nil }
    var interactionBusy: Bool { busy || settlingLock || authenticating }

    init() {
        initializeStorage()
        idleTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                if self.unlocked, self.vault?.isUnlocked() != true { self.lock() }
            }
        }
    }

    private func initializeStorage() {
        guard !preparingStorage, vault == nil, boundary.isActive else { return }
        preparingStorage = true
        let ticket = cancellation.ticket()
        worker.async { [weak self] in
            do {
                let (url, exists, handle) = try ticket.run {
                    let url = try VaultFiles.prepare()
                    try ticket.check()
                    let exists = FileManager.default.fileExists(atPath: url.path)
                    try ticket.check()
                    let handle = try LLVault.open(path: url.path)
                    return (url, exists, handle)
                }
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard ticket.isCurrent, self.boundary.isActive else {
                        handle.requestLock()
                        self.worker.async { handle.close() }
                        return
                    }
                    self.preparingStorage = false
                    self.databaseURL = url
                    self.vault = handle
                    self.hasVault = exists
                    self.ready = true
                    if !self.boundary.isActive { handle.requestLock() }
                }
            } catch {
                DispatchQueue.main.async {
                    guard ticket.isCurrent, let self else { return }
                    self.preparingStorage = false
                    self.status = "无法启用本机受保护存储。"
                }
            }
        }
    }

    private func perform<T>(_ action: @escaping (LLVault) throws -> T, cleanup: @escaping () -> Void = {}, completion: @escaping (Result<T, Error>) -> Void) {
        performChecked({ vault, _ in try action(vault) }, cleanup: cleanup, completion: completion)
    }

    private func performChecked<T>(_ action: @escaping (LLVault, WorkTicket) throws -> T, cleanup: @escaping () -> Void = {}, completion: @escaping (Result<T, Error>) -> Void) {
        let captured: LLVault
        do {
            guard !settlingLock, boundary.isActive, let vault else { throw WorkCancelled() }
            // This Go-issued immutable expected-epoch view is captured on the
            // UI actor before queueing. Worker preflight alone has a gap.
            captured = try vault.captureOperation()
        } catch {
            worker.async { cleanup(); DispatchQueue.main.async { completion(.failure(error)) } }
            return
        }
        let ticket = cancellation.ticket()
        worker.async {
            let result: Result<T, Error> = autoreleasepool {
                Result { try ticket.run(cleanup: cleanup) { try action(captured, ticket) } }
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func sceneInactive() {
        covered = true
        if !authenticating { systemUnlockPending = false }
        boundary.resignActive()
        invalidateUI()
        preparingStorage = false
        vault?.requestLock()
        activeAuthentication?.keychain.cancelAuthentication()
        activeAuthentication = nil
        scheduleLockCleanup()
    }

    func sceneActive() {
        boundary.becomeActive()
        covered = authenticating
        if authenticating {
            continueOwnedAuthenticationIfReady()
            return
        }
        if vault == nil { initializeStorage() } else if !unlocked && !settlingLock { refreshPresence() }
        // Returning from a system prompt never automatically retries unlock.
    }

    func lock() {
        cancelOwnedAuthentication(message: nil)
        boundary.lock()
        invalidateUI()
        vault?.requestLock()
        activeAuthentication?.keychain.cancelAuthentication()
        activeAuthentication = nil
        scheduleLockCleanup()
    }

    private func scheduleLockCleanup() {
        guard let vault else { return }
        let owner = lockCleanup.begin()
        settlingLock = true
        worker.async { [weak self] in
            vault.lock()
            DispatchQueue.main.async {
                guard let self else { return }
                guard self.lockCleanup.finish(owner) else { return }
                self.settlingLock = self.lockCleanup.isPending
                if !self.settlingLock, self.boundary.isActive {
                    if self.authenticating { self.continueOwnedAuthenticationIfReady() }
                    else if !self.unlocked { self.refreshPresence() }
                }
            }
        }
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
        exposure.cancel()
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
        cancellation.invalidate()
        operation.cancel()
        busy = operation.isBusy
    }

    private func refreshPresence() {
        guard let url = databaseURL else { return }
        let ticket = cancellation.ticket()
        worker.async { [weak self] in
            do {
                let exists = try ticket.run {
                    let exists = FileManager.default.fileExists(atPath: url.path)
                    if exists {
                        try ticket.check()
                        try VaultFiles.verifyProtection(directory: url.deletingLastPathComponent())
                        try ticket.check()
                        try VaultFiles.protect(directory: url.deletingLastPathComponent())
                    }
                    return exists
                }
                DispatchQueue.main.async { if ticket.isCurrent { self?.hasVault = exists } }
            } catch {
                DispatchQueue.main.async {
                    guard ticket.isCurrent else { return }
                    self?.lock()
                    self?.ready = false
                    self?.status = "本机文件保护检查失败。"
                }
            }
        }
    }

    func generateAccountKey() {
        guard ready, !interactionBusy, boundary.isActive else { return }
        do {
            var key = try LLVault.generateSecretKey()
            defer { key.resetBytes(in: 0..<key.count) }
            generatedSecretKey = LLVault.formatSecretKey(key)
            backupAcknowledged = false
        } catch { status = "无法生成 Secret Key。" }
    }

    func createVault() {
        guard !hasVault, !interactionBusy, backupAcknowledged, !generatedSecretKey.isEmpty,
              !password.isEmpty, password == confirmation,
              let attempt = boundary.beginUnlock(), let url = databaseURL else { return }
        do {
            let passwordData = NativeSecretBuffer(password)
            let key = NativeSecretBuffer(data: try LLVault.parseSecretKey(generatedSecretKey))
            password = ""; confirmation = ""; generatedSecretKey = ""; backupAcknowledged = false
            let owner = beginOperation()
            performChecked({ vault, ticket in
                try vault.create(password: passwordData.data, secretKey: key.data)
                try ticket.check()
                try VaultFiles.verifyProtection(directory: url.deletingLastPathComponent())
                try ticket.check()
                try VaultFiles.protect(directory: url.deletingLastPathComponent())
            }, cleanup: { passwordData.clear(); key.clear() }, completion: { [weak self] result in
                guard let self else { return }
                guard self.finishOperation(owner), self.boundary.finishUnlock(attempt) else { return }
                self.boundary.lock()
                self.unlocked = false
                self.creatingVault = false
                switch result {
                case .success:
                    self.hasVault = true
                    self.status = "已创建加密金库。请使用两个完整因素解锁。"
                case .failure(let error):
                    self.vault?.requestLock()
                    if error is PlatformProtectionError { self.ready = false }
                    self.status = "创建结果未确认，或本机文件保护检查失败；请检查金库后再操作。"
                    if self.ready { self.refreshPresence() }
                }
            })
        } catch { lock(); status = "Secret Key 格式无效。" }
    }

    func unlockWithFactors() {
        guard hasVault, !interactionBusy, !password.isEmpty, let attempt = boundary.beginUnlock() else { return }
        do {
            let passwordData = NativeSecretBuffer(password)
            let key = NativeSecretBuffer(data: try LLVault.parseSecretKey(secretKey))
            let directory = databaseURL?.deletingLastPathComponent()
            password = ""; secretKey = ""
            let owner = beginOperation()
            performChecked({ vault, ticket in
                if let directory { try VaultFiles.verifyProtection(directory: directory) }
                try ticket.check()
                try vault.unlock(password: passwordData.data, secretKey: key.data)
            }, cleanup: { passwordData.clear(); key.clear() }, completion: { [weak self] result in self?.finishUnlock(result, attempt: attempt, owner: owner) })
        } catch { lock(); status = "Secret Key 格式无效。" }
    }

    func unlockWithSystem() {
        guard ready, hasVault, !interactionBusy, boundary.isActive else { return }
        lock() // preauthentication starts with no open session or visible values
        guard let token = ownedAuthentication.begin(vaultLocked: vault?.isUnlocked() != true, isActive: boundary.isActive, monotonicNow: authenticationMillis()) else { return }
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedCancelTitle = "取消"
        authenticationContext = context
        authenticationToken = token
        authenticationSucceededAt = nil
        authenticating = true
        systemUnlockPending = true
        covered = true
        armAuthenticationTimeout(token, milliseconds: 60_000)
        let ticket = authenticationCancellation.ticket()
        worker.async { [weak self] in
            do {
                try ticket.run {
                    guard try CapsuleKeychain().hasCapsule() else { throw PlatformProtectionError.unavailable }
                    try ticket.check()
                    var error: NSError?
                    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { throw PlatformProtectionError.unavailable }
                    try ticket.check()
                    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "解锁此设备上已启用的 Locklark 金库") { success, _ in
                        let completed = ContinuousClock.now
                        DispatchQueue.main.async {
                            self?.receivedSystemAuthentication(token, context: context, success: success, completed: completed)
                        }
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    guard let self, self.ownedAuthentication.owns(token) else { context.invalidate(); return }
                    self.cancelOwnedAuthentication(message: "本机快速解锁不可用或验证已取消；请使用完整因素。")
                }
            }
        }
    }

    func sceneBackground() {
        cancelOwnedAuthentication(message: nil)
        sceneInactive()
    }

    func cancelSystemAuthentication() {
        let pending = systemUnlockPending
        cancelOwnedAuthentication(message: nil)
        if pending { lock() }
        status = "系统验证已取消。"
    }

    private func cancelOwnedAuthentication(message: String?) {
        authenticationCancellation.invalidate()
        ownedAuthentication.cancel()
        authenticationToken = nil
        authenticationSucceededAt = nil
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
        authenticationContext?.invalidate()
        authenticationContext = nil
        authenticating = false
        systemUnlockPending = false
        if boundary.isActive { covered = false }
        if let message { status = message }
    }

    private func receivedSystemAuthentication(_ token: AuthenticationToken, context: LAContext, success: Bool, completed: ContinuousClock.Instant) {
        guard ownedAuthentication.owns(token), authenticationContext === context else { context.invalidate(); return }
        guard success, ownedAuthentication.systemSucceeded(token, monotonicNow: authenticationMillis(at: completed)) else {
            cancelOwnedAuthentication(message: "系统验证未完成；请重新发起或使用完整因素。")
            return
        }
        context.interactionNotAllowed = true
        authenticationSucceededAt = completed
        let remaining = 10_000 - (authenticationMillis() - authenticationMillis(at: completed))
        guard remaining > 0 else { cancelOwnedAuthentication(message: "系统验证已过期。请重新发起。"); return }
        armAuthenticationTimeout(token, milliseconds: remaining)
        continueOwnedAuthenticationIfReady()
    }

    private func continueOwnedAuthenticationIfReady() {
        guard authenticating, !settlingLock, boundary.isActive,
              let token = authenticationToken, let context = authenticationContext,
              let authenticatedAt = authenticationSucceededAt,
              ownedAuthentication.consume(token, isActive: true, monotonicNow: authenticationMillis()) else { return }
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
        authenticationToken = nil
        authenticationContext = nil
        authenticationSucceededAt = nil
        authenticating = false
        guard let attempt = boundary.beginUnlock() else { context.invalidate(); return }
        let owner = beginOperation()
        let store = NativeSystemUnlockStore(authorization: SystemAuthenticationAuthorization(context: context, authenticatedAt: authenticatedAt))
        activeAuthentication = store
        let directory = databaseURL?.deletingLastPathComponent()
        performChecked({ vault, ticket in
            if let directory { try VaultFiles.verifyProtection(directory: directory) }
            try ticket.check()
            try vault.unlockWithSystem(store)
        }, completion: { [weak self] result in self?.finishUnlock(result, attempt: attempt, owner: owner) })
    }

    private func armAuthenticationTimeout(_ token: AuthenticationToken, milliseconds: Int64) {
        authenticationTimeout?.cancel()
        authenticationTimeout = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(milliseconds)) } catch { return }
            guard !Task.isCancelled, let self, self.ownedAuthentication.owns(token) else { return }
            self.cancelOwnedAuthentication(message: "系统验证已过期。请重新发起。")
        }
    }

    private func authenticationMillis(at instant: ContinuousClock.Instant = .now) -> Int64 {
        let value = authenticationClockOrigin.duration(to: instant).components
        return value.seconds * 1_000 + value.attoseconds / 1_000_000_000_000_000
    }

    private func finishUnlock(_ result: Result<Void, Error>, attempt: ScreenToken, owner: OperationToken) {
        guard finishOperation(owner), boundary.finishUnlock(attempt) else { return }
        activeAuthentication = nil
        systemUnlockPending = false
        covered = false
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
        guard let token = boundary.capture(), !interactionBusy else { return }
        let owner = beginOperation()
        let store = NativeSystemUnlockStore()
        activeAuthentication = store
        perform({ vault in
            if enable { try vault.enableSystemUnlock(store) } else { try vault.disableSystemUnlock(store) }
        }, completion: { [weak self] result in
            guard let self, self.finishOperation(owner), self.boundary.permits(token) else { return }
            self.activeAuthentication = nil
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
        guard !settlingLock, let token = boundary.capture() else { return }
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
        guard let row = selected, !interactionBusy else { return }
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
                self.perform({ _ in try handle.take() }, cleanup: { handle.clear() }, completion: { [weak self] taken in
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
                        let exposureOwner = self.exposure.begin()
                        let started = ContinuousClock.now
                        self.revealed = VisibleText.secret(text)
                        self.status = "仅本次显示；验证码不会自动取下一期。"
                        self.expiryTask = Task { [weak self] in
                            while !Task.isCancelled {
                                do { try await Task.sleep(for: .milliseconds(100)) } catch { return }
                                guard !Task.isCancelled, let self, self.exposure.owns(exposureOwner) else { return }
                                let elapsed = started.duration(to: .now).components
                                let milliseconds = elapsed.seconds * 1_000 + elapsed.attoseconds / 1_000_000_000_000_000
                                if !self.boundary.permits(token) || self.vault?.isUnlocked() != true ||
                                    !budget.permits(wallNow: Self.wallNow(), elapsedMilliseconds: milliseconds) {
                                    if self.exposure.expire(exposureOwner) { self.clearDisclosure() }
                                    return
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
        guard creatingLogin, !interactionBusy, let token = boundary.capture(), !titleDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let title = titleDraft, url = urlDraft, generate = generatePassword
        let user = NativeSecretBuffer(usernameDraft), value = NativeSecretBuffer(passwordDraft)
        clearDrafts()
        creatingLogin = false
        mutate(token: token, cleanup: { user.clear(); value.clear() }) { vault in
            if generate { return try vault.generateLogin(title: title, url: url, username: user.data, length: 24) }
            return try vault.createLogin(title: title, url: url, username: user.data, password: value.data)
        }
    }

    func saveEdit() {
        guard let row = selected, let field = editingField, !interactionBusy, let token = boundary.capture() else { return }
        let value = NativeSecretBuffer(editDraft)
        clearDrafts()
        editingField = nil
        mutate(token: token, cleanup: { value.clear() }) { vault in
            return try vault.edit(id: row.identifier, revision: row.revision, field: field, value: value.data)
        }
    }

    func regenerate() {
        guard let row = selected, !interactionBusy, let token = boundary.capture() else { return }
        clearDisclosure()
        mutate(token: token) { try $0.regenerate(id: row.identifier, revision: row.revision, length: 24) }
    }

    private func mutate(token: ScreenToken, cleanup: @escaping () -> Void = {}, action: @escaping (LLVault) throws -> LLReceipt) {
        let owner = beginOperation()
        let directory = databaseURL?.deletingLastPathComponent()
        performChecked({ vault, ticket in
            let receipt = try action(vault)
            if let directory {
                try ticket.check()
                try VaultFiles.verifyProtection(directory: directory)
                try ticket.check()
                try VaultFiles.protect(directory: directory)
            }
            return receipt
        }, cleanup: cleanup, completion: { [weak self] result in
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
