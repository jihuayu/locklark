# 桌面快捷搜索验收

基线 main `20e27aa48b6ac855e027cc7abde64fc3c56591f7`，分支 `codex/desktop-quick-search`。前批浏览器OTP [PR #29](https://github.com/jihuayu/locklark/pull/29) 的精确head `ced61e5391c19d761e3ded615d5afd4074b20906` 已经四项 [CI 42133038819](https://github.com/jihuayu/locklark/actions/runs/42133038819) 通过并合并。

按 [功能与架构](desktop-quick-search-design.md) 推进：主代理设计及独立验收，Sol xhigh负责MyGo实现与外部验收工具，Luna max独立review。当前实现及集成验收进行中，以下按阶段记录证据；保留基线行为失败、修复、固定二进制、真实全局快捷键/原生日常回归、敏感值扫描及精确head远端检查门槛。

## 失败先行

`/tmp/locklark-validation/desktop-quick-search-ui-red.log` 保留现有MyGo View的真实行为失败：测试尝试点击“快捷搜索”，现有界面缺少入口。测试调用现有UI测试器，不依赖尚未存在的新产品API；不是编译失败。修复及真实全局快捷键验收仍待完成。

## 首个固定实现与本地检查

候选v1：`/tmp/locklark-tools/desktop-quick-search-v1/locklark-desktop`，SHA256 `9010e8db6d931cae4b01d7c0c6df65bc5e3fdc9e93db2762b212707b1e75d586`；同目录 `product-source.sha256` 固定147个产品源码/模块文件，主代理独立核对全部匹配。后续工具/测试须独立记录，不把此摘要当作它们的固定版本。

Sol桌面全包测试通过（13.875s，`desktop-quick-search-desktop-all.log`），新增11个顶层quick测试及6个表驱动子例。定向race通过（69.478s，`desktop-quick-search-race.log`），desktop vet及Windows amd64 / Darwin arm64测试交叉编译通过（`desktop-quick-search-vet.log`、`desktop-quick-search-*-build.log`）。覆盖真实Session.RequestLock在查询/选择前生效、单一worker与迟到释放、输入变更撤旧结果、忙态不扰动、草稿关闭保留/明确选择导航及Tab/Enter/Escape。Luna定向Go/UI复跑已通过，最终代码与完整工具review仍待收齐。

## 真实显示环境准备

Sol首轮真实基线 `desktop-quick-search-baseline-red.log`（state `clkkkmd4`）记录foreign focus成立、一次键批次，但native focus在3秒内未成立；95为无窗口管理器的裸Xorg，不能将此轮称为“快捷键仅唤起、缺面板”的产品失败。随后在隔离95增加真实xfwm4再核；主代理独立94亦在确认无WM后启动xfwm4，EWMH `_NET_SUPPORTING_WM_CHECK` 已存在。不会以验收工具主动聚焦替代全局快捷键的激活证明，原轮证据保留。

## v1 非空 Escape 行为失败

Sol补充真实UI测试发现MyGo SearchField在非空查询时吞掉Escape并清文字，外层面板不能按约定关闭；`desktop-quick-search-escape-red.log` 保留行为失败。Luna此前v1定向11组测试通过与代码无阻塞不覆盖这一新边界。v1不覆盖、不作为最终版本，窄修改普通TextInput并保持原label、提交及焦点契约，随后重验非空Escape与键盘选择并固定v2。

带WM的真实基线轮 `desktop-quick-search-baseline-wm-red.log`（state `wxffsrcv`）先确认双向EWMH WM_CHECK；外部窗口获得前台，一次Ctrl+Shift+L键批次后16ms内原生窗口获得焦点，随后固定原因 `quick-panel-unavailable`，旧搜索控件存在、新面板不存在，exit 1且隐私扫描通过。这一轮才是旧实现仅唤起而无搜索面板的真实行为red。

## 固定候选 v2

普通TextInput修复后，desktop全包通过（13.148s），非空输入→Enter认证查询→Tab×3→Enter选精确ID/修订，以及非空Escape关闭/草稿保留的定向测试通过（1.732s）；对应两项UI定向race通过（10.649s，`desktop-quick-search-v2-ui-race.log`），vet通过。Luna对TextInput增量无阻塞，独立Escape/焦点测试通过（0.617s）。

`/tmp/locklark-tools/desktop-quick-search-v2/locklark-desktop` SHA256 `a7eee1641d9f53d1faa7722a82531a31f6696981bb5a889d857c9e1e88cc723c`。同目录147项产品manifest摘要 `3141c63b6f5d0a7d4717e503b0e375ea2b0966aad262da2d1c1641ef1e2eac91`，主代理独立核对产品与二进制全部匹配。v1继续保留但不作为最终验收构建。

## 主代理旧桌面日常完整回归

固定v2在独立94显示与真实xfwm4上执行 `dbus-run-session -- python3 scripts/desktop_native_acceptance.py`，以 `LOCKLARK_DESKTOP_HOST` 指向上述v2，exit 0。日志 `desktop-quick-search-v2-parent-daily.log`，私有state `fj7biazb`。真实原子新建/生成、精确重新生成、旧修订/取消、系统剪贴板provider与后续所有者、独立Python HMAC的TOTP显示/复制/期限及锁定均通过，全部私有artifact/controller canary扫描通过。主代理又对完整重定向输出（含DBus）独立扫描夹具因素变体及运行期间全部相关OTP窗口，通过；不把这项外层扫描扩称为独立重建所有已替换随机密码。

Sol另外完成v2的Windows amd64/Darwin arm64 desktop测试包交叉编译（`desktop-quick-search-v2-{windows,darwin}-build.log`），不沿用v1来声称v2已验证，更不将交叉编译当作物理快捷键或托盘实测。

## 验收 oracle 与工具集成修正

父代理检查发现最初工具和Go元数据测试使用reveal类事件识别披露，遗漏真正桌面的 `item.desktop.show.*` / `item.desktop.copy.*`；工具显示探针还曾把expected列表传到otp位置。两处均为验收判断错误，不据此宣称产品取值越权。Go以四个真实PrepareField的用户名/密码show/copy意图作正对照，保留 `desktop-quick-search-oracle-red.log` → `desktop-quick-search-oracle-green.log`；修复仅测试，v2产品不变。工具使用正确动作和 `display(expected=...)`，另以ID集合完整且无重复替代仅逐行membership/总数相等。Luna独立相关Python工具39/39通过，GUI工具尚需最终集成证明。

工具draft1六项manifest由主代理独立核对匹配。父代理完整quick尝试（`desktop-quick-search-v2-parent-draft1.log`，state `2msbexxa`）首轮真实快捷键11ms内唤起，自动焦点、Enter查询及3条完整活动ID metadata通过，Tab已聚焦正确目标；在第二次唤起建立辅助窗口前台时ShortcutFailure，未完成实际选择或披露，整轮exit1。Sol95运行则在第11次唤起前失败；前面的明确取值/草稿保存/忙态/迟到查询场景已越过，但同样不能写为整轮通过。两轮均保留。工具draft2将只抬升自己辅助窗口的WM frame后执行一次实际点击/按键，并增加固定失败阶段；不改产品、不通过工具主动聚焦产品来冒充快捷键成功。

## 最终真实链路（v2 / 工具 draft3）

Sol95在工具draft2完整GUI通过（`desktop-quick-search-v2-tools-draft2-gui.log`，state `i2umpb8j`），包括第11次wake和全部scenarios/隐私扫描。draft3相对draft2仅加成功/失败proof持久化、phase/bool/int白名单与对应测试，以及CI接入，不改变产品动作。最终10项工具manifest为 `desktop-quick-search-tools-draft3.sha256`，主代理独立核对全匹配，147项产品manifest也再次匹配。

主代理94独立执行 `dbus-run-session -- python3 scripts/desktop_quick_search_acceptance.py`，`LOCKLARK_DESKTOP_HOST` 指向固定v2，字体配置与旧桌面验收一致，exit 0。日志 `desktop-quick-search-v2-parent-draft3.log`，私有state `xfkzufkw`。7组完整场景通过：打开不自动查询/披露、Enter查询精确活动ID集合、Tab/Enter选择及重复唤起保留焦点、明确审计show/copy及新开面板清理本应用曝光、非空Escape保留草稿并由后续显式保存证明、忙操作不受干扰、单查询槽/关重开丢旧结果和锁定/解锁不自动续跑。主代理另读取proof确认EWMH就绪、11次唤起各只有一批快捷键且native focus全部成功。

全部私有artifact/controller扫描通过，主代理还对含DBus的完整重定向输出独立扫描所有夹具因素变体及运行期间OTP窗口，通过。最终工具单测64项通过；Luna已独立复核此前oracle/metadata/只读barrier并运行39项相关工具测试，最终诊断与CI增量结论随后记录。

CI新增xfwm4依赖与单独的真实quick GUI步骤（私有DBus/Xvfb、绑定已构建desktop）；Python discover覆盖新 `test_desktop_quick_native.py`，macOS筛选加入TestQuick，旧日常/浏览器/OTP/Next.js门槛全部保留。精确head远端CI仍须PR提交后核验，不能用本地成功代替。

Luna对最终draft3工具/诊断/CI增量复核无阻塞，独立64/64 native工具测试、py_compile、diff检查及10项manifest核对通过；Luna未运行真实GUI，GUI的独立证据为上述父代理94。最终工具manifest本身SHA256 `8e50113fd839c9b8723cfbe50208f779bf443bf195d162ffe91a077b6a288310`。
