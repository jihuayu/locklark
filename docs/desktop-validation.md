# MyGo 原生桌面与系统快捷解锁验收

本文保留初始桌面批次的历史证据。后续当前行为：剪贴板改用系统 ownership lease，见[日常桌面验收](desktop-daily-validation.md)；全局快捷搜索见[快捷搜索验收](desktop-quick-search-validation.md)；导入 profile 已扩展为 `login-notes-v2`，原生备注与迁移见[登录备注验收](login-notes-validation.md)。下述 `login-v1` 和剪贴板比较内容的描述属于初始批次。

基线 `5b0ce38`，分支 `codex/desktop-browser`；本批只关闭有证据的桌面基础能力，不关闭持续任务中的 Next.js、完整迁移、浏览器扩展、手机、团队同步或发布范围。

## 实现

MyGo v0.7.4 原生 UI：新建/完整解锁、选取金库、标题搜索、显示/复制、逐字段编辑、归档/回收站、活动、体检、现有 login-v1 导入及加密 KDBX 导出。显示 15 秒、剪贴板 30 秒后尽力清除，仅清当前内容仍匹配本次复制的剪贴板；系统历史可能保留。闲置 5 分钟、收到系统锁屏/睡眠事件或退出时锁定。托盘和全局快捷键依赖桌面环境服务。

Session 只保留已解开的身份材料，不保留主密码/Secret Key或条目缓存。操作串行且重新验证密钥槽、快照和审计；字段只在事务提交及文件关闭后，通过不可 JSON 编码的一次性原生 lease 交付。锁请求原子阻止新动作，界面先清空，不等待磁盘/系统提示；已进入原子事务的变更可能完成。OS 提示返回后已经观察到取消的结果不得继续进入解锁事务/界面；取消若与已开始的事务交错，事务和成功审计可能已经提交，但不返回会话或接纳界面结果。OS 操作开始以最后一次取消检查为界，已开始的提示不能承诺强制取消；OS 提示自身仍须用户在系统窗口取消，不能保证所有 OS API 可被程序关闭。Go/系统 UI 分配的字符串不能保证物理擦除。

系统快捷解锁必须由完整解锁会话主动启用，绑定绝对路径和密钥槽摘要。截止时间固定于该次完整解锁后的 24 小时，快捷解锁不能刷新。它是本地墙钟策略，非抗时钟回拨保证。启用记录为 intent；OS 写入失败/取消/进程中断不能误记成功。系统记录清理失败时结果未知；需要完整解锁后重试停用，不能声称平台记录已删除。

- Windows：只使用 Microsoft Passport Key Storage Provider；非导出 RSA 密钥解开随机 AES-GCM 包装密钥，Credential Manager 仅保存密文；强制 NgcCacheType 和每次 gesture 属性，属性不支持则拒绝。RSA-OAEP/SHA-256 不支持时拒绝，无软件 KSP、DPAPI-only 或布尔提示降级。
- macOS：Security.framework 设备本地、WhenUnlocked 钥匙串，SecAccessControlUserPresence（Touch ID 或系统密码）。需要原生 CGO 构建；CGO 关闭时明确不支持，不退回普通钥匙串。**还必须用 Developer ID 签名的 `.app` 并带 `keychain-access-groups`**；ad-hoc 裸二进制（`go run`/`go build`）没有该 entitlement，`SecItemAdd` 返回 `-34018`，不能把此状态说成可用的 Touch ID。`UserPresence` 接受 Mac 登录密码，不是纯生物识别；签名、entitlement 和真机验收步骤见 [macOS 文档](../macos/README.md)。
- Linux：MyGo Secret Service/libsecret；无服务时拒绝；已打开的系统钥匙串可能不提示，同用户程序可能访问。它不是逐次生物识别保证。

参考：[1Password 使用](https://support.1password.com/windows-hello/)、[1Password 安全属性](https://support.1password.com/windows-hello-security/)、[Microsoft CNG 属性](https://learn.microsoft.com/windows/win32/seccng/key-storage-property-identifiers)、[Passport KSP 名称](https://learn.microsoft.com/en-us/uwp/api/windows.security.cryptography.certificates.keystorageprovidernames.passportkeystorageprovider)。

## 验证记录

失败先行日志在执行环境 `/tmp/locklark-validation`：`desktop-session-red.log`、`desktop-ui-red.log`、`desktop-unicode-red.log`、`system-unlock-red.log`、`system-prompt-lock-red.log`（最后一项实际复现 OS 提示阻塞锁定）。

已实际运行 Linux Xorg dummy 显示服务器及 MyGo 原生窗口，使用 XTest 键鼠输入合成金库路径、主密码和 Secret Key，完成解锁与条目显示；截图 `desktop-window.png`、`desktop-unlocked.png`。这不是 Hello、Keychain 或真机锁屏验收。

工具链由 Go 1.26.8 升到 MyGo 所需 1.27.3；搜索 Unicode 数据随之升到 17，审计绑定 profile 更新为 `title-nfc-fold-substring-u17-v2`，不能将新结果称为原 Unicode 15 profile。

Luna/max 首轮复核发现锁清理时序、系统认证持锁、CNG 指针存活、OS 写入前成功审计问题；已加入取消/锁竞争测试并修复，Luna/max 最终复审通过，无可复现阻断。最终 head `bb5965751250cf957e8fe629588a8db7e0a6f3a8` 的 [CI 42044135997](https://github.com/jihuayu/locklark/actions/runs/42044135997) 全部通过：Ubuntu 3m4s、Windows 7m38s、macOS 33s；PR #23 已合入 main `de7ba5a`。

本地完整 `go test -count=1 ./...`（独立 PyKeePass 与 Bun 环境）通过；`go vet ./...` 通过。桌面/会话定向 race、系统提示取消 race、真实金库 UI 工作流 race 通过；标题搜索 PTY 验收通过。已创建 [PR #23](https://github.com/jihuayu/locklark/pull/23)，三平台 CI 已通过并合并。新增选择上下文检查：切换条目/页面后，已准备字段被销毁，不能迟到显示在另一条目下。

## 尚待真实平台验收

Windows Hello 每次解密提示、拒绝/取消、TPM 清除/密钥失效、休眠锁屏、系统时间变化；macOS 原生编译及签名后的 Touch ID/密码提示、Keychain 权限变化；Linux Secret Service 锁定/取消与 GNOME/KDE 锁屏通知；三平台剪贴板管理器、窗口关闭/托盘与密码字符串残留边界。跨编译和 fake Store 测试不替代这些条目。完整产品和安全认证未完成。

2026-11-09 的 macOS 27.0.1 arm64 实测补记：Touch ID 硬件可用（`LAContext` biometryType=touchID，`bioutil` 已启用），但 `go build` 的 ad-hoc 二进制在 `SecItemAdd`（ACL=UserPresence）上返回 `-34018 errSecMissingEntitlement`；`osunlock.Store` 与 `Session.EnableSystemUnlock` 均失败，UI 曾误报“金库已锁定”。现已把该失败分类为 `ErrMissingEntitlement`/`ErrSystemUnlockUnavailable`，并增加签名提示；`mygo.config.ts`、`macos/locklark.entitlements.plist.template` 与 `scripts/macos_release.sh` 提供签名 `.app` 的构建入口。**签名后的成功 Touch ID 提示仍未取得验收回执**，不能把本记录当作已完成的生物识别验收。

2026-11-09 第二轮 macOS 审计补记：新增 `osunlock.Biometry()` 能力探测（`canEvaluatePolicy` 不弹提示），安全设置显示“系统验证：Touch ID / 系统密码 / 不可用”，无 Touch ID 时文案不再声称会弹 Touch ID；补充 `errSecAuthFailed(-25293)`、`errSecNotAvailable(-25291)`、`errSecServiceNotAvailable(-67585)`、`errSecInteractionRequired(-25315)` 的分类与 UI 文案；修复 passkey 原生适配器失败时返回 `-1` 导致错误分类丢失的问题。新增 `scripts/macos_verify_touchid.sh` 检查 ad-hoc、TeamIdentifier、`keychain-access-groups`、embedded profile、codesign、Gatekeeper 与 stapling。自签名证书实验：`codesign` 可签名但 `TeamIdentifier=not set`，带 keychain group 的进程被 AMFI SIGKILL（exit 137），`security verify-cert` 为 `CSSMERR_TP_NOT_TRUSTED`，因此不能替代 Apple Developer ID；成功 Touch ID 验收仍被签名身份阻塞。
