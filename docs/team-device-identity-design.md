# 本地团队设备身份基础

本片只实现 `internal/teamclient` 的独立设备身份与双钥持有证明，供仓库内原生协调层使用。它没有创建团队、邀请交换、网络同步、公开 profile 的磁盘持久化或 owner/publisher 管理界面，不能称为已完成的团队客户端。系统保护是否可用须由各平台真实验收证明；单元测试的 fake Store 只验证调用与所有权边界。

## API 与身份绑定

```go
type SystemStore interface {
    Store(string, []byte) error
    Load(string) ([]byte, error)
    Delete(string) error
}

PrepareDevice(trustedPins directory.Pins) (*DevicePlan, error)
(*DevicePlan).Descriptor() DeviceDescriptor
(*DevicePlan).Protect(context.Context, SystemStore) (DeviceDescriptor, error)
(*DevicePlan).Close()

NewDeviceOperation(trustedPins directory.Pins, expected DeviceDescriptor) (*DeviceOperation, error)
(*DeviceOperation).Descriptor() DeviceDescriptor
(*DeviceOperation).Load(context.Context, SystemStore) error
(*DeviceOperation).AnswerChallenge(directory.Enrollment, directory.Challenge) (directory.Admission, error)
(*DeviceOperation).Close()
```

`SystemStore` 与现有 `osunlock.Store` 结构兼容；没有普通文件、环境变量、个人库或 private-key getter 回退。`Store` 在调用期间借用输入，若需保留必须由实现复制；`Load` 交出的可变缓冲由调用方接管并清理，包括 error 同时返回缓冲的情况。本层不调用 `Delete`，也不自动重试 OS 写入。

每次准备生成彼此独立的随机安装/profile/device ID、age 解密身份和 Ed25519 签名种子，不复用个人库或其他团队角色的密钥。公开 descriptor 只有版本、设备角色、三个 ID、scope、独立可信 pins、双公钥与本地状态。pins 深复制并采用既有 WriterACL+possession 配置校验；没有服务器发现或信任降级。

系统记录 ID 是独立用途域加完整公开绑定的 SHA-256；与个人快捷解锁 ID 没有互换含义。OS 保护的有界信封绑定版本、角色、安装/profile/device ID、scope、完整 pins 与双公钥，独立记录 age 身份和签名种子。加载要求规范且精确的绑定字节，拒绝额外/重复字段、截断、超限和尾部数据，并重新派生两把公钥。它没有引入新的加密协议：秘密依赖真实系统服务保护，入网证明仍调用原 `directory.AnswerChallenge`。

## 一次保护操作

`preparing` 表示尚未授出 Store-attempt 开始许可；`pending` 仅表示 OS 保护已成功返回，不表示入网；`unknown` 表示已授出开始许可但未得到可接受的成功结果。没有 `active` 状态。

调用方可以先取得 descriptor，供未来持久协调层记录原身份。`Protect` 最多尝试一次：短锁中与取消/Close 仲裁，授出 Store-attempt 开始许可后释放锁再调用 OS。这不是 OS 与内存状态原子提交。许可之后，即使尚未实际进入 OS 函数，取消、Close 或 OS error 都保留原 descriptor 并返回 unknown；许可之前取消则保持 preparing，确定没有 Store 调用。只有成功确认先赢，才返回 pending，后来的 Close 不会假装撤销已完成的保护。

本片尚未实现 durable public profile，因此不声称崩溃恢复闭环。写入结果未知时不生成替代身份、不盲删记录；未来协调层只能基于原 descriptor 显式创建新 operation，加载并核验同一身份。

## 一次加载与入网证明

operation 在 OS 调用前创建，允许 Close 同步撤销迟到输出。Load 最多一次，OS 前后都检查取消；不持短锁跨 OS。Close 清理当前归属本 handle 的缓冲，worker 正在使用的缓冲由 worker 返回后清理。Close 不等待也不能保证中断系统对话框或阻塞的 OS 调用。

`AnswerChallenge` 第一次 attempt 就消耗 operation，包含格式/绑定拒绝。调用方必须独立取得 expected enrollment；不能直接复制未核对 challenge。新加入设备的精确 parent checkpoint 必须来自已有独立 anchor 的 owner 可信渠道，不能来自服务器、缓存或默认 Genesis。Genesis 只用于真正首次 bootstrap，本层不能替调用方证明这个来源。

本层检查自身 profile/scope 与双公钥，并复用目录协议核验 owner、成员、parent、加密 nonce 和签名。私钥只在 operation 内和独占 worker 使用，没有普通导出 API。输出前再次通过短锁与 Close/取消仲裁；输出许可先赢后，已返回的公开 Admission 不可撤回。这只是双钥持有证明，不授予成员资格、reader/writer 角色或任何 owner/publisher 密钥；挑战本身没有时间期限。所有已入网设备可读整份快照，reader 仅限制写，固定 pins 没有原位角色密钥轮换能力。

公开 handle 可复制但共享同一状态；String/GoString 固定遮蔽，JSON 序列化拒绝。可变秘密缓冲显式清理；Go 字符串、age 内部对象及 OS 服务副本无法由本层保证物理擦除。同一系统用户恶意程序不是这些软件身份可隔离的安全边界。

## 已完成的 Linux 系统服务验收

实现代理和主代理分别构建夹具，并在各自新建的私有 D-Bus、HOME/XDG 目录和真实 GNOME Keyring Secret Service 中通过 13 组验收。使用的原生适配器是 `osunlock.New()`，包含跨进程 Store/Load/Delete、独立 `secret-tool` 核对、服务缺失时拒绝且没有文件回退、设备保护、全新进程双钥证明、错误目标消耗操作、服务停止后拒绝、重启后恢复原身份、所属进程清理及已知 canary 扫描。工具另有 8 组负测；核心单元测试、race 和 vet 通过。

复跑入口为 `scripts/team_identity_acceptance.py` 与 `scripts/team_identity_fixture`。工具先核验固定 Debian 包及解包内容，在独立总线中确认服务 PID，再运行实际系统调用。每次必须使用新的私有证据目录，不连接用户已有密钥库。

这些结果证明 Linux 系统服务保护和双钥持有；不证明逐次系统提示、生物识别、Windows/macOS 成功路径或已获得团队成员资格。扫描覆盖夹具已知的合成秘密及运行文件，未导出内部随机设备私钥来伪造完整 canary 覆盖。公开 profile 的持久化和真实团队 bootstrap 仍须单独实现与验收。
