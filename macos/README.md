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

## 系统验证能力与错误码

安全设置会显示 `osunlock.Biometry()` 的结果，不会触发验证提示：

- `Touch ID`：当前 Mac 已启用 Touch ID，`UserPresence` 会优先弹 Touch ID，也可回退到系统密码。
- `系统密码`：`canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` 当前不可用，但系统密码策略可用。
- `不可用`：两者都不可用；系统快捷解锁不应启用，请使用完整解锁。

Security.framework 的失败会映射为固定错误和固定 UI 文案，不把原生错误文本或密钥材料带到界面：

| OSStatus | 含义 | 产品行为 |
| --- | --- | --- |
| `-34018` | `errSecMissingEntitlement` | 提示当前构建缺少签名权限；重新签名，不要重试到死循环 |
| `-128` | `errSecUserCanceled` | 提示已取消，可继续用主密码与 Secret Key |
| `-25293` | `errSecAuthFailed` | 提示系统验证未通过，可重试，不误报为钥匙串损坏 |
| `-25308` / `-25315` | interaction not allowed / required | 提示当前无法显示系统验证（如锁屏），解锁 Mac 后重试 |
| `-25291` / `-67585` | keychain/service not available | 提示钥匙串暂不可用，可稍后重试或重启 Mac |
| `-25300` | `errSecItemNotFound` | 提示尚未启用，而不是“金库已锁定” |

## 快速静态检查

用 `scripts/macos_verify_touchid.sh` 先排除最常见的打包/签名错误：

```bash
./scripts/macos_verify_touchid.sh /Applications/Locklark.app
```

它检查 ad-hoc、TeamIdentifier、`keychain-access-groups`、`embedded.provisionprofile`、`codesign --verify`、Gatekeeper 和 stapling。静态检查通过后才进入 UI 验收。

**自签名证书不能替代 Developer ID。** 本机实测：用自签名 code-signing 证书 `codesign --sign` 可以成功，但 `codesign -dv` 仍显示 `TeamIdentifier=not set`；带 `keychain-access-groups` 的进程会被 AMFI `SIGKILL`（exit 137），`security verify-cert` 也返回 `CSSMERR_TP_NOT_TRUSTED`。必须使用 Apple 签发的 Developer ID Application 身份和匹配的 provisioning profile。

## 验收

```bash
codesign -d --entitlements :- /Applications/Locklark.app 2>&1 | grep -A2 keychain-access-groups
codesign --verify --deep --strict --verbose=2 /Applications/Locklark.app
```

在签名版里：

1. `./scripts/macos_verify_touchid.sh /Applications/Locklark.app` 全部 PASS。
2. 完整解锁金库，打开安全设置；应显示“系统验证：Touch ID”或“系统验证：系统密码”。
3. 点“启用系统快捷解锁”；应出现 Touch ID / 系统密码提示（或在 enrollment 后首次解锁时出现）。
4. 成功后锁定，点“使用 Touch ID / 系统密码解锁”，确认无需主密码 + Secret Key 即可恢复会话。
5. 再验证 Passkey 的系统验证按钮会为新操作重新提示；取消后应提示已取消，而不是“金库已锁定”。

失败时不要用 `go run` 的结果判断功能：先确认运行的是签名 `.app`，并且 `codesign -d --entitlements` 中有 `keychain-access-groups`。

## 安全取舍

`kSecAccessControlUserPresence` 接受 **Touch ID 或 Mac 登录密码**，且在增删指纹后仍然可用。拥有 Mac 登录密码的人可以在 24 小时内用快捷解锁打开金库，绕过主密码 + Secret Key。如果产品要求“仅 Touch ID”，应改用 `kSecAccessControlBiometryCurrentSet`（指纹变更即失效），并为无 Touch ID 的 Mac 显式提供受限回退；同时更新 UI 文案和威胁模型。当前代码与文案明确写的是“Touch ID / 系统密码”，不要把这条路径宣传成纯生物识别。
