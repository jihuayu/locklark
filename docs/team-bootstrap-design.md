# 首个团队 bootstrap 的持久协调

本片提供仓库内原生/CLI 可调用的 bootstrap API：服务独立身份 → 独立核对服务公钥 → 单 owner 与独立 publisher、首设备 → 签名加密空库 artifact → 服务初始化 → 首设备真实 HTTPS Fetch 并解密空库。没有邀请、多 owner 分发、密钥轮换、团队编辑或普通条目披露接口；不能将这条创建路径描述为完整团队客户端。

## 公开接口

- `PrepareSequencer(profilePath)` 返回 opaque `SequencerPlan`。`Descriptor` 是公开身份，`Protect(ctx, SystemStore)` 最多一次，`Close` 只撤销/清理本地 handle。
- `PrepareOwnerBootstrap(profilePath, reviewedSequencer, anchorPath)` 返回 opaque `OwnerPlan`。单 owner、publisher、首设备是独立随机密钥，完整 pins 在设备生成之前确定。`Protect` 分别保护三个角色；部分成功不会自动补写或删除。
- `OpenOwnerBootstrap(profilePath).BuildInitial(ctx, SystemStore)` 只构造空 `[]vault.Item{}`，使用现有 `IssueChallenge`、设备 `AnswerChallenge`、`VerifyAdmission` 和 `directory.Build`。`EncodeBootstrapArtifact`/`DecodeBootstrapArtifact` 只处理公开证明及加密快照，限制 16MiB，拒绝未知/重复字段、尾部、非规范编码和错误初始状态。
- `InitializeService(ctx, profilePath, ServiceInitRequest, SystemStore)` 要求既有本地服务 profile；request 独立提供 `Expected` 服务 descriptor、`TrustedPins`、artifact 与精确 DB/anchor 路径。不能只相信 artifact 自报的 pins。`ReconcileServiceInitialization` 只处理这个原意图。
- `OpenService(ctx, profilePath, expectedService, trustedPins, SystemStore)` 返回拥有 `teamsync.ManagedHandler` 的 opaque `ServiceOperation`。`Handler` 没有 key getter；`Close` 同步撤销新请求和输出许可，不等待磁盘或网络。
- `ConfirmInitial(ctx, ownerProfilePath, trustedPins, SystemStore, teamsync.Endpoint)` 使用首设备自己的 HTTP 签名、完整历史及独立 anchor，再在内部解密快照；本片只接受空条目集，返回 checkpoint/device ID/item count，不返回私钥或秘密条目。
- `ReadSequencerDescriptor`、`ReadOwnerDescriptor`、`ReadBootstrapStatus` 是未验证的本地记录投影；字段名 `RecordedState` 不代表新鲜网络授权。`ReconcileProtection` 只 Load 原 OS 记录，绝不 Store/Delete。

这些调用可能等待系统认证、磁盘或 HTTPS，必须在 worker 执行。取消/Close 先在短内存锁失效；短锁不跨 OS、磁盘或网络。OS 调用正在使用的缓冲由 worker 独占，在返回后清理；不承诺中断系统服务或物理清除 Go/age/OS 中所有副本。

## 持久记录与独立互斥

每个新 profile 是私有 bbolt 文件，只含公开身份、角色操作阶段、原 artifact 和初始化意图。创建先完整写入临时文件，再以不覆盖方式发布；临时清理核对原 inode/file ID，不删除替代文件或 symlink。Unix 检查可信父链、0600、regular file 和单 hardlink；Windows 使用受限 DACL、可信父链与文件身份。路径在创建前解析父目录，拒绝最终 symlink 和文件别名；DB、anchor、profile 及保留的 identity-lease 路径不得重合。

独立 `profilePath.identity-lease` 文件串行同一身份的 OS 转换及协调操作，产品永不删除或替换它。它独立于可恢复的 profile DB inode，所以单独恢复 profile 不会制造第二个 lease。跨进程 lease 可以跨阻塞工作持有；它不是 UI/Session 的短取消锁，Close 不等待它释放。

所有公钥和原 descriptor 先持久记录，才允许 OS Store。每个 Store-attempt 先记录 unknown，再执行 OS；失败、取消或丢失确认不能说成未写。只有正向 Load、完整绑定和公钥重派生核验通过，才可显式恢复同一记录；缺失/拒绝/服务不可用不能区分为权威 absence，绝不由此覆盖或重新生成私钥。profile 创建后、尚未保护的私钥若随进程丢失，本片可能只能保持 preparing 并放弃这份未启用 profile，不假装能恢复未保存的密钥。

角色 envelope 使用现有 OS Store，不引入新的加密协议。新 envelope 保存固定用途域及规范公开绑定的 SHA-256，包含角色、版本、profile/install ID、原规范 profile 路径、完整 pins/scope、公钥；owner/publisher 还绑定固定 anchor、成员及首设备公钥。加载重新计算绑定并派生公钥。固定上限 1400 字节兼容当前最小平台容量；设备基础信封格式保持不变，聚合准备在任何 OS 写入前检查同一上限。没有普通文件、环境变量、argv 或个人库回退。

## 服务从 unbound 到 bound

服务身份必须在 scope 存在前生成并系统保护。其 OS envelope 起初为 `unbound`，已经绑定服务公钥、随机 IDs 和原规范 profile 路径。唯一转换是正向 Load 并重新派生核对这个原 unbound 身份，在同一 identity lease 内一次 Store 成 `bound`。bound target digest 覆盖完整 pins、scope、原 canonical artifact 摘要和精确 DB/anchor 路径。

公开 profile 不能单独充当转换凭据：恢复旧 profile 不能改变 OS 中的 bound 状态；将 profile 复制到另一位置也不能通过 OS 路径绑定。bound 只接受相同原 target 对账，异 scope、异 artifact 或换 anchor/DB 路径均拒绝。Store-attempt 后不确定且 OS 仍为 unbound，也保持 unknown，不自动再次 Store。macOS 替换失败可能使旧记录不可加载，这同样只能拒绝，不能悄悄重建。

服务初始化的固定顺序：

1. 先校验独立 expected/pins 与纯公开 `directory.VerifyInitial`；原 artifact 和路径意图在任何 OS mutation/Create 前持久化。
2. 正向 OS Load 原身份；unbound 时，先创建或打开精确 Genesis server anchor。
3. 持久化绑定 attempt，再一次 Store 成 bound。
4. **只有这次调用亲自成功完成 fresh binding 的 worker** 能调用一次 `directory.Create`。任何入口开始时已经 Load 到 bound，都只能核验现有 DB 与现有 anchor，不能创建任一文件。
5. 现有 DB 必须完整验历史且初始 proposal/snapshot 与原意图完全一致，才可将既有 Genesis anchor 推进到原 receipt。最后持久记录 active。

因此 crash 在 bound Store 之后、DB 创建之前，或者 Create 结果未知且 DB 缺失时，可能永久保持 unknown；不会为了可用性再次签名或 Create。已绑定服务缺少 anchor 也拒绝，不从 DB 头或旧公开 phase 重建。DB、独立 anchor 与 profile 不是跨存储原子事务。

## owner outbox 与首次读取

OwnerPrepare 在任何 OS 角色写入之前，一次创建独立 Genesis client anchor；之后 Open/Confirm 只打开既有 anchor，不创建。Genesis 仅属于本机这次真正的新 scope 创建，不能用于已有团队设备加入。

新 Build 先打开既有原 client anchor，只有精确 Genesis 才允许继续；缺失或已推进均在 OS 加载/签名前拒绝。owner 的版本化 OS 记录还具有 `unbuilt → claimed(BuildID) → built(BuildID, artifact digest)` 一次状态机，不能只依赖可回滚公开 profile 的 attempt 标记。正向 Load 原 unbuilt 后，先持久化随机 BuildID/claim attempt，再一次 Store 为 claimed；只有这次成功的 worker 可以 IssueChallenge/Build/签名。原 artifact 全部 canonical 字节先落盘，再持久 finalize attempt 并一次 Store 为 built，确认精确 BuildID/digest 后才导出。两个 OS 更新均保持原 owner seed 和用途绑定，没有私钥导出。

恢复时 claimed 无原 artifact 永久 unknown；claimed 即便已有 outbox，本片也保守地不自动重试 finalize Store。built 加匹配原 BuildID/digest 的 outbox 才能 Load 后返回原字节，不再 Build/签名/Store。公开 profile 即使回滚到 Build 前、client anchor 仍是 Genesis，OS claimed/built 也会阻止另一个原 artifact。built 的原 outbox 已丢失时保持 unknown，可能只能放弃这份 profile；不声称完整自动恢复。角色部分保护或 OS 拒绝不产生可导出 artifact。

ConfirmInitial 先正向验证 OS 保护的 owner profile 绑定（固定 anchor/pins/member/device），但 HTTP 仍使用首设备 signer。Fetch 验 nonce、新鲜观察、完整历史和原第一 proposal，并持久推进独立 anchor；设备内部 age/KDBX 解密后核对空快照上下文。只有本地 active 记录也成功落盘才返回 active。丢失最终记录或确认时保留原 outbox，下一次只对账它；不会重置检查点或用 owner HTTP 权限代替首设备资格。

## 边界与验证

服务原 sequencer、owner/publisher、首设备私钥不进入 artifact、网络、status、普通 JSON 或个人备份；opaque handles 的 String/GoString 固定遮蔽且 MarshalJSON 拒绝。实际系统服务可能已解锁而不再次提示，不能把 Linux Secret Service 称为逐次生物识别。

单独恢复公开 profile/cache 不能重绑已绑定服务或重建其 DB/anchor；OS Store、独立 anchor/lease 和主机的恶意整体回滚不在保证内。同一系统用户恶意替换整个可信本地状态不是软件身份可隔离的边界。已授出的目录 commit/已开始的响应写出也不可撤回；关闭后的结果可能未知。

Go 回归覆盖真实 TLS DeviceClient/age/KDBX 全链路、部分 Store、迟到取消、实际子进程 lease、profile 回滚/复制、scope/anchor/DB 替换、缺失 anchor/DB、严格 artifact 与原 outbox。fake Store 只证明边界；各平台真实 OS 成功、CLI 与重启断点必须由独立验收另行记录，交叉编译不计平台成功。
