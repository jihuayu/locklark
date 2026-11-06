# 使用本地 SSH agent

桌面 MyGo 的“SSH 密钥”页管理 Ed25519 密钥，并为每次签名显示本机批准窗口。它不会把私钥交给 SSH 客户端，不会替换系统 agent，也不会修改 shell 配置。

## 创建或导入密钥

1. 用既有完整因素或已启用的系统快捷解锁打开个人库，进入“SSH 密钥”。
2. 填写“SSH 密钥标题”，选择“生成 Ed25519 密钥”。导入现有密钥时，填写标题，选择“选择未加密 OpenSSH 私钥…”，再点击“确认导入未加密 Ed25519 私钥”。生成成功会清空标题，下次导入须重新填写。
3. 选择该条目，点击“复制 SSH 公钥”，把公钥添加到目标账户的 `authorized_keys` 或服务的 SSH key 设置中。复制内容只有规范的公钥行，不含标题、选项或私钥。

首批仅接受未加密的 OpenSSH Ed25519 私钥；加密私钥、RSA 和其他算法会被拒绝。导入不会删除原文件；原文件仍需由你保管。库内私钥没有普通读取或导出入口。

## Linux 与 macOS 客户端配置

点击“开启本地 SSH agent”，再点击“复制 SSH_AUTH_SOCK 端点”。以下示例中的路径须替换为本次界面显示的完整端点。单条命令设置只影响本次子进程：

```sh
SSH_AUTH_SOCK='/界面复制的完整端点' /usr/bin/ssh-add -L
SSH_AUTH_SOCK='/界面复制的完整端点' /usr/bin/ssh user@example.com
```

`ssh-add -L` 只列出活动密钥的公钥，不弹签名批准。不要使用 `ssh-add 私钥文件`：添加、删除、解锁及扩展协议不受支持，密钥通过 MyGo 管理。

也可为单个 Host 显式配置端点，不改变其他 Host 使用的 agent：

```sshconfig
Host my-server
    HostName example.com
    User alice
    IdentityAgent /界面复制的完整端点
```

端点含空格时须按 OpenSSH 配置语法加引号。若库内有多个公钥，可把复制的公钥保存为本地 `.pub` 文件，并在该 Host 中设置 `IdentityFile /公钥文件路径` 和 `IdentitiesOnly yes`；该文件只需包含公钥。可用以下命令检查指定公钥的签名，此操作也需要本机批准：

```sh
SSH_AUTH_SOCK='/界面复制的完整端点' /usr/bin/ssh-add -T /公钥文件路径
```

## Windows 客户端配置

Windows 使用单独的用户管道，界面复制的端点形如 `\\.\pipe\Locklark-SSH-agent-…`。用 Windows 自带 OpenSSH 时，可在 PowerShell 中临时设置端点，并在完成后恢复原值。下面的占位内容须整体替换为界面复制的完整端点：

```powershell
$previousAgent = $env:SSH_AUTH_SOCK
try {
    $env:SSH_AUTH_SOCK = '从界面复制的完整端点'
    & "$env:WINDIR\System32\OpenSSH\ssh-add.exe" -L
    & "$env:WINDIR\System32\OpenSSH\ssh.exe" user@example.com
} finally {
    if ($null -eq $previousAgent) {
        Remove-Item Env:SSH_AUTH_SOCK -ErrorAction SilentlyContinue
    } else {
        $env:SSH_AUTH_SOCK = $previousAgent
    }
}
```

不要替换系统的 `openssh-ssh-agent` 管道。Git 或其他程序若使用自带的 SSH 实现，须确认它支持 Windows named pipe；本批实际验证的是 Windows 系统目录中的 OpenSSH。GitHub CLI 的 HTTP API 凭据使用独立的 `personal run-cli --profile gh`，SSH 签名不能代替 HTTP token。

## 逐次批准与转发

签名窗口显示精确密钥及修订、指纹、系统取得的本机用户与连接建立时的 PID/进程信息、算法、flags、签名数据字节数和 SHA256 摘要、请求及连接编号、截止时间。只在你确实发起该次操作时点击“仅批准本次 SSH 签名”；否则拒绝或停止 agent。每个请求最长等待30秒，没有记住批准或整批批准。一次连接可能需要多次签名。

窗口始终标注“目的地未验证”：普通 agent 请求没有可信主机名，进程信息也不证明程序可信。`ssh -A` 会把 agent 能力转发给远端；经转发触发的签名仍需本机批准，但服务不能识别或阻止所有转发，不能把显示的本地 SSH 进程理解为远端主机证明。不要批准无法对应到自己操作的请求。

批准表示允许本次本地签名交付，不表示远端登录成功。已经交付的签名、已经建立的远端连接不会因随后锁库而被撤回。

## 停止、归档与恢复

“停止本地 SSH agent”、锁库和退出都会撤销待批准请求并关闭端点。解锁后须手动重新开启服务；客户端不会触发自动解锁。若提示端点清理结果未确认，检查残留端点和进程，不要把未知清理状态当作成功。

管理页提供“活动 SSH 密钥”“已归档 SSH 密钥”“SSH 回收站”和“全部 SSH 密钥”。归档或移入回收站会使该密钥退出 agent 列表并撤销旧请求；可在对应范围取消归档或恢复。仅活动密钥可签名。相同公钥对应多个活动条目时签名拒绝，请先归档重复条目，使批准能唯一对应一个条目。

## 平台验证状态

`436cfab` 的 Linux、macOS、Windows 本机 CI 都已通过真实 OpenSSH 的 `ssh-add -L`、`ssh-add -T` 和 SSH 连接；Windows 系统客户端文件版本为9.5.6.4，同用户身份和管道 ACL 检查也已实际执行。Linux 的完整 MyGo 16组验收在主代理独立重建、长临时目录和该版 Web CI 中全部通过，包含真实两跳 `ssh -A` 与每跳独立批准。

macOS/Windows 的 OpenSSH 传输验证不能代替完整原生界面或系统生物识别真机验证。Windows RunCLI 的外部 ConPTY 验收仍在修正独立工具的目录验证；它不影响上述已通过的 SSH 传输结果。交叉编译不代表运行验收通过。
