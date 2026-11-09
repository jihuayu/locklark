# Passkey 迁移 CLI：完整工作流

日期：2026-11-08（香港）。范围为 #52 的原生 CLI 入口。当前已实现并提交六个动作：

- `personal passkey-invite`
- `personal passkey-revoke`
- `personal passkey-list`
- `personal passkey-export`
- `personal passkey-plan`
- `personal passkey-import`

## 入口与隔离

`runPersonal` 在通用参数解析之前用精确动作名分派到本流程；只有上面六个动作会进入，其他动作继续走原有解析器，不会被前缀匹配误路由。流程只调用已解锁的 `personal.Session` 原生迁移 API，不直接打开数据库，不读取原始凭据记录，也不接触用户句柄、私钥或凭据种子。`PlanPasskeyTransfer` / `ApplyPasskeyTransfer` 仍是当前审计链、修订和限额的最终权威。

## 命令

```text
personal passkey-invite --file PATH --out NEW --ttl SECONDS
personal passkey-revoke --file PATH --invitation FILE
personal passkey-list   --file PATH
personal passkey-export --file PATH --invitation FILE --target-pin HEX64 --selection PRIVATE_JSON --out NEW_PACKET
personal passkey-plan   --file PATH --invitation FILE --packet FILE --source-pin HEX64
personal passkey-import --file PATH --invitation FILE --packet FILE --source-pin HEX64 --digest HEX64 --mapping PRIVATE_JSON
```

- `--file` 是现有加密金库路径。
- `--out` 必须是**不存在**的绝对路径；写入 owner-only 私有文件。
- `--ttl` 是规范十进制秒数，范围 1..900（15 分钟）。
- `--invitation` 是 owner-only 私有邀请文件（<= 16 KiB）。
- `--packet` 是 owner-only 私有密文包（<= 2 MiB）。
- `--target-pin` / `--source-pin` / `--digest` 是公开的规范小写 64 位十六进制值，绝不来自 argv 之外的秘密通道，也绝不接受大写或非十六进制。
- `--selection` / `--mapping` 是 owner-only 私有 JSON（<= 192 KiB）。

所有输入/输出路径按绝对、clean 路径校验；`teamfiles.Distinct` 禁止任何输出、输入或金库互相别名。写文件的命令在**任何因素提示、同意短语和数据库变更之前**用 `teamfiles.CheckNew` 检查目标不存在。

## 完整工作流

1. **接收端**生成邀请：`passkey-invite`。回执给出 `invitation_id`、公开 `fingerprint` 和 `expires_at`。用户必须在两台设备上通过独立可信通道核对指纹。
2. **源端**列出可导出的公开元数据：`passkey-list`。选择精确的 `item_id` / 父 `revision` / `credential_id` / 子 `credential_revision`。
3. **源端**导出：`passkey-export --target-pin <接收端指纹>`。回执给出 `packet_id`、`source_fingerprint`、`target_fingerprint`。密文包只写入私有文件。
4. **接收端**预览：`passkey-plan --source-pin <源端指纹>`。只读，不解密到 stdout，不消费邀请；输出公开 `digest`、过期时间、指纹和分组/候选目标。
5. **接收端**导入：`passkey-import --source-pin ... --digest ... --mapping ...`。在一次事务内重新验证邀请链、指纹、过期、修订和映射，并消费邀请。回执只给出发生变化的父条目 ID/修订。
6. **接收端**验证：用普通 Session API 对该凭据执行断言，并在依赖方侧独立验证签名。CLI 不声称远端备份、平台认证器或硬件保证。

## 选择器 JSON（`--selection`）

只接受一个 JSON 数组，1..16 个对象，每个对象必须恰好包含四个小写、精确的键：

```json
[{"item_id":"...","revision":"<64 hex>","credential_id":"<base64url>","credential_revision":"<64 hex>"}]
```

拒绝未知键、重复键、大小写别名（如 `ITEM_ID`）、嵌套/非字符串值、缺失键、尾随数据、非法 UTF-8、非法修订值、非法 credential ID 以及超过 16 条记录。`passkey-list` 输出的四个公开选择器字段可直接组成该文档。

## 映射 JSON（`--mapping`）

只接受一个 JSON 数组，1..16 个对象，每个对象必须是下面两种精确形状之一：

```json
[
  {"group_id":"<64 hex>","existing_target_id":"...","existing_revision":"<64 hex>"},
  {"group_id":"<64 hex>","new_title":"...","new_username":"..."}
]
```

- `group_id` 必须来自 `passkey-plan` 的公开分组。
- 现有条目分支必须同时给出 `existing_target_id` 与精确 `existing_revision`，且不得混入新条目键。
- 新条目分支必须显式给出 `new_title` 与 `new_username`（`new_username` 可为空字符串），不得混入现有条目键。
- 拒绝未知键、重复键、大小写别名、混合分支、缺失键、嵌套/非字符串值、原始凭据/私钥/种子键、尾随数据、非法 UTF-8、非法分组/修订值以及超过 16 个分组。原生 Apply 仍会重新验证这些映射。

## 列表输出

`passkey-list` 是只读公开元数据投影：只使用 `Session.List("active")` 与 `Session.ReadManagedPasskeysMetadata(false)`，不调用 `ReadAuthenticatedItems`，不返回原始记录、私钥、用户句柄或凭据种子：

```json
[{"item_id":"...","revision":"<parent>","credentials":[{"credential_id":"...","credential_revision":"<child>","rp_id":"...","name":"..."}]}]
```

## 两个因素与隐藏短语

主密码和 Secret Key 都通过现有控制终端隐藏输入读取，绝不来自 argv 或环境变量。终端在执行期间保持 raw 模式；退出、信号或错误都会恢复终端模式。

隐藏、精确匹配的同意短语：

- `passkey-invite`：`INVITE`
- `passkey-revoke`：`REVOKE`
- `passkey-export`：`EXPORT`
- `passkey-plan`：`PLAN`
- `passkey-import`：`IMPORT`

`passkey-plan` 和 `passkey-import` 在短语之前打印完整的、带引号的 source pin 摘要；`passkey-import` 同时打印完整 digest 与分组数；`passkey-export` 打印完整 target pin。`passkey-list` 是只读的，不需要短语。

### 因素新鲜度（原生 API 硬约束）

`personal.Session` 的五个迁移入口（`NewPasskeyTransferInvitation`、`RevokePasskeyTransferInvitation`、`ExportPasskeyTransfer`、`PlanPasskeyTransfer`、`ApplyPasskeyTransfer`）共享同一个授权检查：当前解锁必须带有**非零、非未来、年龄 < 15 分钟**的完整因素证明。15 分钟是显式上限，与原生会话最大空闲和邀请最大 TTL 一致；它从完整解锁时刻起算，普通读写活动（包括刷新空闲计时的列表/读取）**不会**延长它。

该检查在打开数据库、解密包和释放任何新输出之前执行，并在赢得提交许可之前再执行一次。零值（例如 OS 快速解锁会话）、未来时间或已到窗口的证明一律返回固定的 `ErrFullFactorRequired`：不写审计、不改条目、不消费邀请、不返回邀请/包/回执。普通条目标题/备注/密码编辑、列表、搜索等非迁移行为不受影响，仍按原有空闲语义工作。

CLI 每次动作都重新读取主密码和 Secret Key，构成一次新的完整解锁，因此总是满足该检查；本节把这一既有行为固化为原生 API 的强制约束，而不是新增提示或新的失败路径。

## 回执白名单

```json
// passkey-invite
{"status":"invited","invitation_id":"...","fingerprint":"...","expires_at":"..."}

// passkey-revoke
{"status":"revoked"}

// passkey-export
{"status":"exported","packet_id":"...","source_fingerprint":"...","target_fingerprint":"..."}

// passkey-plan（原生 Plan 的公开 allowlist）
{"digest":"...","invitation_id":"...","expires_at":"...","source_fingerprint":"...","target_fingerprint":"...","groups":[...]}

// passkey-import
{"status":"imported","items":[{"id":"...","revision":"..."}]}
```

任何回执都不包含原始邀请、密文包、recipient、审计公钥、签名、用户句柄、私钥或凭据种子。

## 失败语义

- 因素错误或终端不可用：固定拒绝，不提示同意，不写文件，不改数据库。
- 短语不匹配：固定取消错误，不写文件，不改数据库。
- `CheckNew`/`Distinct`/`Read`/选择器或映射解析在同意和变更之前失败：固定拒绝，数据库未被触碰。
- 邀请过期、已撤销、已消费、指纹不符、修订过期、映射不匹配、重复凭据或超限：由原生 Plan/Apply 整批拒绝，不写入部分条目、不消费邀请、不重放。
- 数据库变更成功（或可能已提交）后写文件失败：返回固定的 publication UNKNOWN 错误，**不返回原始字节、不自动重试、不删除或覆盖不属于本次操作的输出**。
- `passkey-import` 在提交成功后回执写出失败：同样返回固定 UNKNOWN，而不是原始 writer 错误或“确认失败”。
- 金库变更与文件系统发布**不是**一个原子事务；本流程不承诺跨数据库和文件系统的原子性。
- 导出不删除源凭据；导入不声称远端备份、平台认证器、UV 或硬件保证；本地删除不是分布式吊销。

## 验收状态

自动化覆盖：两套独立金库、邀请→导出→计划→导入→导入后断言签名验证、取消、无覆盖、错误文件权限、伪造选择器/映射、过期/撤销/重复消费、无部分导入、公开回执白名单和固定 UNKNOWN 语义。

文件权限按平台原生语义验证，而不是用 POSIX 模式位代替：Unix 使用 owner-only `0600` 私有文件与 `0700` 私有根目录；Windows 使用显式的所有者加受保护 DACL，负例安装真实的 Everyone 读取 ACE（`os.Chmod` 在 Windows 只切换只读属性，无法表达私有性）。测试用生产私有读取器重新打开邀请/密文包，并按平台断言所有者、DACL 保护标志与受信主体，未放宽任何生产私有输入检查。`scripts/passkey_transfer_fixture` 的私有根目录同样按平台校验（Unix `0700`，Windows 所有者加受保护 DACL）。

**#52 的最终关闭仍需要两台真实设备的授权迁移与平台/硬件提供者共存证据。** 自动化双金库测试不能替代“两台真实设备”的证据。
