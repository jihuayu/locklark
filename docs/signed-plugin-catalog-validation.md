# 离线签名插件目录

从 main `8659bb9`（PR #19 已经 Luna/max 与 Ubuntu/Windows CI 合并）接续第六条产品线。新增 `plugin init/inspect/install/list/audit/revoke`，管理签名的静态包；没有第三方执行入口、依赖下载、安装脚本或自动工具授权。所有状态报告明确返回 `execution: disabled`。现有内嵌 Bun 插件不从此目录加载代码，本批不把它改称操作系统沙箱。

## 使用与信任来源

从可信发布者取得包、插件 ID 和 Ed25519 公钥，并独立核对公钥。自行维护可信 JSON 公钥配置，例如键为 `example.tools/pull-reader`，值为已核对的 64 位小写十六进制公钥。`--pins` 必须来自本地操作者控制的配置，不能从包或远端目录自动生成；所有已安装和已撤销 ID 都要保留公钥。

```text
locklark plugin init --file NEW_CATALOG.db
locklark plugin inspect --package release.llplugin --id PLUGIN_ID --publisher PUBLIC_KEY
locklark plugin install --file CATALOG.db --parent CHECKPOINT --pins trusted-pins.json --package release.llplugin --id PLUGIN_ID --publisher PUBLIC_KEY --digest INSPECTED_DIGEST
locklark plugin list --file CATALOG.db --anchor CHECKPOINT --pins trusted-pins.json
locklark plugin audit --file CATALOG.db --anchor CHECKPOINT --pins trusted-pins.json
locklark plugin revoke --file CATALOG.db --parent CHECKPOINT --pins trusted-pins.json --id PLUGIN_ID
```

保存 `init` 返回的第一个 checkpoint，并在每次成功变更后独立保存新 checkpoint。读取要求提供的 anchor 出现在完整事件链中；写入还要求 parent 精确等于当前 head。并发提交只有一个成功，失败方须读取当前目录重新评估，不能自动替换 parent 重试。旧 anchor 只能拒绝回滚到那个点之前，不能证明它之后的状态没被回滚。不能从现存数据库自动重新建立信任起点。

安装前先 inspect 静态包，核对声明能力和依赖锁，install 再要求完整包 digest；安装时只读取一次有界字节，并对同一份内存副本验签/提交。升级必须同 ID、同公钥且数值版本严格增加；同版本重复安装、同版本不同内容、降级和更换公钥均拒绝。`revoke` 是这个目录中的永久 ID 墓碑，所有后续版本都拒绝；没有重新启用、原地换发布者或信任根迁移入口。不要通过重建目录来冒充保留原撤销历史的升级。

包、包清单和本地事件都是明文管理数据，不用于保存凭据。目录文件 Unix 创建权限为 0600；Windows 继承调用者控制目录的 ACL。此入口是本地操作者的管理命令，没有金库解锁或远程审批含义，MCP 不因此获得安装或执行权限。

## 包协议与边界

`Release` 是固定字段顺序的规范 JSON：schema=1、ID、单调数值 version、publisher、runtime=`bun-1.4.4/bundled-v1`、capabilities、dependencies、bundle、signature。Go `pluginstore.Sign` 提供构建辅助；[独立 Python 验收脚本](../scripts/plugin_acceptance.py) 展示另一实现的编码与 Ed25519 签名。签名输入为 `locklark/plugin-package/signature/v1` + NUL + 将 signature 置 null 后的规范 JSON；最终包不附加换行。digest 覆盖带签名的完整规范包，使用独立 `locklark/plugin-package/digest/v1` 域。

拒绝未知/重复字段、字段重排、空白、替代大小写、非规范数值/base64/hex、错误签名与 ID/公钥串用。JS 以标准 base64 编码。包最多 2 MiB，JS 最多 1 MiB、必须非空 UTF-8 且无 NUL。ID 是有界 ASCII namespace/name，保留 `locklark.builtin/`；绝不按 ID 解包成路径。

当前仅认识声明能力 `github.pulls.get`，安装不会授予它。依赖锁最多 64 项，名称严格有序且唯一，每项指定普通 `x.y.z` 数值版本和 SHA256；版本范围、latest、URL、未知能力和超限整包拒绝。预发布版本/其他包协议尚未支持。依赖锁是发布者签署的来源声明，本批不会下载或核对依赖源码，也不能证明 JS 是该依赖集的可复现构建，更不能证明包行为符合能力声明。

## 持久化与验证

本地 bbolt 在同一默认同步事务写入完整签名包与事件；重读时重放版本、固定发布者和撤销规则，并用独立 pins 验证每个当前包及最后撤销包。升级前的包内容不全部保留，旧事件只保留 digest；这不是全版本发布者签名证据库。最多 32 个 ID（含撤销墓碑）、4096 个事件；文件在映射前限制为 256 MiB，写入也使用 bbolt 原生 MaxSize 限制（包括分配增长）。容量满后拒绝变更，现有状态仍可读取。

Luna/max 复核建议补充的物理大小限制已落实：超大稀疏文件在打开回调中拒绝，另以较小测试配额触发 bbolt 真实提交阶段的增长失败，确认不返回回执且原 head 仍可读取。Windows named-pipe 源路径尚无专门原生负测；本批要求操作者使用可信本地普通文件路径。

创建通过同目录临时文件完成事务和关闭，再不覆盖发布；Unix 同步父目录，Windows 使用 write-through move。失败不返回成功状态。提交后 close 或 stdout 失败时，操作可能已生效，旧 anchor 仍可用于重读较新状态。初建回执丢失且没有可信 checkpoint 时不自动恢复信任；已有路径不会覆盖。硬件掉电和安全擦除未验收，也不承诺删除历史页面。

事件 hash 链绑定随机 catalog ID、序号、操作和前序摘要，但**不是操作者数字签名**。它依赖可信本地文件系统和独立保存的 checkpoint，不抵御同一系统用户主动伪造未锚定后缀，也不是远端最新状态证明。不得把该目录当作不可信服务器的授权源。

失败先行 `/tmp/locklark-validation/plugin-catalog-red.log`：缺少包/目录 API。Go 测试覆盖签名字段篡改、规范编码、固定 pin、单调升级、撤销证明保留、祖先/错误目录检查点、整文件回滚、同父并发、事务回滚、关闭/输出失败、容量边界、有界普通文件和 Linux FIFO/符号链接拒绝。`scripts/plugin_acceptance.py` 用独立 PyCryptodome Ed25519 生成包，经独立 CLI 进程完成检查、安装、升级、并发、撤销和回滚拒绝。包内包含创建文件的 JS，整个测试确认没有执行；这证明本管理路径不执行代码，**不是**恶意插件沙箱逃逸验收。

本地命令：带 PyKeePass/Bun 的 `go test -count=1 ./...`、插件目录/CLI 定向 `go test -race`、`go vet ./...`、独立 Python 验收、`git diff --check`。最终 Luna/max 实现复核、精确 head 与原生 Ubuntu/Windows CI 以本批 PR 为准。第三方 OS 隔离、运行授权、发行者远端撤销服务、安装更新 UI 和 Next.js 管理界面仍待完成。
