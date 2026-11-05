# Next.js 本机管理界面验收

基线为 MyGo 桌面 PR #23 合并后的 main `de7ba5a65fe33e948eb5f405a0dd9b72ca12c4b2`。本批提供真实本地签名团队目录的只读管理视图，不把查看界面标为完整邀请、权限变更、远端同步或浏览器填充实现。

## 范围与边界

Next.js 16.4.5 / React 19.3.1，概览、成员、设备、连接与安全页面，搜索及窄屏布局。Go `locklark-management` 从启动时固定的目录、可信 pins/policy/checkpoint 配置读取并验证历史与快照，再投影成员 ID、角色、设备 ID、检查点与读取时间。快照密文、字段、设备公钥/私钥均不进入网页 DTO。页面说明本地验签不证明远端最新，也不宣称同步完成。

Go 仅监听 `127.0.0.1` 随机端口，独立 256-bit bearer，仅固定 `GET /v1/summary`；校验实际 loopback peer 与精确 Host，拒绝任何 Origin、请求体、查询路径、Forwarded、HEAD/OPTIONS 和其他操作。请求头/响应/时间/并发有界，错误固定、无部分元数据、无 CORS。每次都重新读取并验证目录，不返回旧缓存。

可信配置在 Unix 要求当前用户拥有、不可被 group/other 写；沿原始与解析路径核验祖先所有者/可写性，可信 sticky 临时目录允许；拒绝最终 symlink，以非阻塞/不跟随链接方式打开后核对句柄。Windows 核验文件与祖先 owner/DACL，拒绝其他普通账户可写、改权限或替换已有路径；当前用户、SYSTEM、Administrators、TrustedInstaller 属于本机信任边界。管理员或当前 OS 用户的恶意程序不在本机访问隔离范围内。

连接文件的全部父目录必须可信，禁止其他普通账户替换既有路径；读端在所有平台复用 Go 校验句柄、owner/DACL/目录链和私密读取权限。Node 启动器通过受限 helper 私有 stdout pipe 获取三字段连接记录，Windows 不再只依赖 mode 位。连接文件新建、不覆盖；Unix 0600，Windows 创建时设受保护当前用户 DACL。SIGINT/SIGTERM 清理与当前进程匹配的文件；强杀/崩溃可能留下旧文件，必须确认旧服务已结束后显式处理，不自动覆盖。Node 启动器只读取一次固定连接文件（开发模式需要 Go；可用 `LOCKLARK_MANAGEMENT_EXECUTABLE` 指定预编译 helper 的绝对路径），运行时仅用直接 `node:http` 请求固定 loopback endpoint；不使用环境代理、重定向、动态路径或重试。

浏览器使用独立 256-bit 一次性连接码（从启动起 5 分钟，最多 12 次尝试）交换 30 分钟随机会话，HttpOnly/Secure/SameSite=Strict host-only cookie；会话仅在单个常驻 Node 进程内有效，重启失效，退出撤销。写路由校验精确 Host/Origin/Fetch Metadata，登录体积/时长有界；代码不进 URL。cookie不按端口隔离，同一 OS 用户的其他本机进程属于上述本机信任边界。到期、读取失败、发起退出时清空已显示的元数据；退出响应丢失也不保留旧名单。

动态页面、状态接口禁缓存；逐响应 nonce CSP，无第三方脚本、unsafe-inline 或 unsafe-eval，禁止框架嵌入、外部连接与 referrer。关键设计依据：[Next.js Proxy](https://nextjs.org/docs/app/getting-started/proxy)、[CSP](https://nextjs.org/docs/app/guides/content-security-policy)、[Route Handlers](https://nextjs.org/docs/app/api-reference/file-conventions/route)。不是公网部署、无服务器多实例或反向代理配置；不得直接暴露端口到网络。

## 实际验证

失败先行：`/tmp/locklark-validation/management-broker-red.log`（缺少 broker API）、`management-web-red.log`（缺少会话边界模块）。

本地通过：Go broker 单元/竞态、真实签名目录投影与 checkpoint 回滚拒绝；配置权限与连接文件不覆盖；TypeScript、8 项 Web 安全测试、生产 `next build`。使用真实合成签名目录及真实 Go broker → Next.js → 浏览器，Chrome for Testing 156（Playwright Chromium）和 Firefox 157 已跑通登录、一次码重放拒绝、成员/设备筛选、390px布局、目录损坏/恢复、断开服务端已撤销但响应丢失、cookie撤销、跨源/伪造Host/直接broker拒绝。不是 mock 数据源，也不是用户真实团队。

截图在 `web/.test-state/`（忽略提交）：connect、overview、mobile-devices。自动扫描 SSR HTML、客户端 bundle、状态响应不含 runtime bearer/连接码/合成金库字段。增量修复后 Chromium 17.1s、Firefox 13.1s 的完整流程通过，包括真实 SIGTERM/SIGINT 清理和同路径重启。曾有一轮 Chromium 在 page fixture 冷启动阶段超时，测试上限改为 60 秒后重跑通过，没有更改请求/断言超时。完整 CI 与 Luna/max 最终复审证据待补。

已按 React 检查技能核对：客户端只接收明确投影、无原始服务对象；鉴权先于数据访问；受控表单有标签、按钮可键盘操作、导航声明当前位置；派生列表在渲染计算，只有会话计时需要 effect；无跨会话结果缓存或外部字体/分析脚本。

## 尚未完成

公网多用户部署、团队创建/邀请/吊销的原生签署流程、远端密文同步与新鲜度、浏览器扩展配对/填充/保存/更新、Safari 实测及手机系统集成继续保留。这个本机只读浏览器界面不授予解锁、签署或字段读取权限。
