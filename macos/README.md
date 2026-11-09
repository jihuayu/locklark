# macOS 签名、Touch ID 与快捷解锁

`go build` / `go run` 生成的是 **ad-hoc 签名的裸二进制**。它没有稳定的 bundle ID、Team ID 或 `keychain-access-groups`，因此 macOS 的 data protection keychain 会拒绝带 `SecAccessControl` 的项，`SecItemAdd` 返回 `-34018 (errSecMissingEntitlement)`。这不是“金库已锁定”，而是当前构建没有签名权限。

要验证真实的 Touch ID / 系统密码解锁，必须：

1. 用 `mygo build` 生成 `.app`，而不是直接运行裸二进制。
2. 用 Apple Developer Program 的 **Developer ID Application** 证书签名。
3. 使用授权 `app.locklark.desktop` 的 **Developer ID provisioning profile**，并包含 `keychain-access-groups`（见 `locklark.entitlements.plist.template`）。
4. 可选：提交 Apple notarization 并 stapling。

## 构建签名版

先在 Apple Developer 门户创建：

- App ID：`app.locklark.desktop`，启用 Keychain Sharing，group 同为 `app.locklark.desktop`。
- Developer ID provisioning profile，绑定该 App ID 和签名证书。

然后：

```bash
export LOCKLARK_MACOS_SIGNING_IDENTITY="Developer ID Application: Your Name (ABCDE12345)"
export LOCKLARK_TEAM_ID="ABCDE12345"
export LOCKLARK_MACOS_PROVISIONING_PROFILE="$PWD/macos/locklark.provisionprofile"
export LOCKLARK_NOTARY_PROFILE="notary"   # xcrun notarytool store-credentials notary
./scripts/macos_release.sh
```

脚本会把模板中的 `TEAMID` 替换成实际 Team ID，写出 `.mygo-release/locklark.entitlements.plist`，再调用固定版本的 MyGo CLI 构建 `darwin/universal` 的 `.app`/DMG。构建产物在 `out/` 或 `-o` 指定的目录；`.mygo-release/` 和 provisioning profile 不应提交。

不带签名环境变量时，`mygo build` 仍会生成 ad-hoc `.app`。它可以用于检查窗口、菜单栏/Dock 身份和打包布局，但 **Touch ID 仍不可用**；请使用主密码与 Secret Key。注意 MyGo 默认 `CGO_ENABLED=0`，会编译进“系统解锁不可用”的兜底实现；开发和验收时必须显式 `CGO_ENABLED=1`（`scripts/macos_release.sh` 已设置）。

## 验收

```bash
codesign -d --entitlements :- /Applications/Locklark.app 2>&1 | grep -A2 keychain-access-groups
codesign --verify --deep --strict --verbose=2 /Applications/Locklark.app
```

在签名版里：

1. 完整解锁金库。
2. 打开安全设置，点“启用系统快捷解锁”。
3. 应出现 Touch ID / 系统密码提示；成功后锁定并点“使用 Touch ID / 系统密码解锁”。
4. 再验证 Passkey 的系统验证按钮会为新操作重新提示。

失败时不要用 `go run` 的结果判断功能：先确认运行的是签名 `.app`，并且 `codesign -d --entitlements` 中有 `keychain-access-groups`。

## 安全取舍

`kSecAccessControlUserPresence` 接受 **Touch ID 或 Mac 登录密码**，且在增删指纹后仍然可用。拥有 Mac 登录密码的人可以在 24 小时内用快捷解锁打开金库，绕过主密码 + Secret Key。如果产品要求“仅 Touch ID”，应改用 `kSecAccessControlBiometryCurrentSet`（指纹变更即失效），并为无 Touch ID 的 Mac 显式提供受限回退；同时更新 UI 文案和威胁模型。当前代码与文案明确写的是“Touch ID / 系统密码”，不要把这条路径宣传成纯生物识别。
