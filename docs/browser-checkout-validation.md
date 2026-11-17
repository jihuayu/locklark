# 结算 iframe 验收

2026-11-09，Linux / 真实 Edge，源码 `63c5a5851a0741ba7147b4b687a7ab410c26bbcf`，实际原生宿主与桌面物理审批。

- 同站跨源 child frame：审批后仅填 PAN、CVV、持卡人和有效期；顶层与 PIN 保持空白，不自动提交。
- 物理拒绝：零字段写入。
- 不同站点 checkout.other.test：拒绝字段交付，表单保持空白。
- opaque sandbox：不提供可填目标，表单保持空白。
- 原生审批等待期间替换 child document：旧批准无法填入新文档，无额外自动批准。
- 页内 picker：打开与取消各一次物理点击；期间对真实 `#detail-fill` 的 DOM `.click()` 被接收为 `isTrusted === false`，picker 不出现，两处表单保持空白，无原生或资料审批。

403 项整合 Node 检查通过（397 扩展检查与 6 项驱动检查）；此前整合后的 host / desktop / personal race 检查通过。CI 新增同一真实浏览器旅程。以上是增量证据，不代表重跑所有 E2E，也不声明所有浏览器或平台均已验证。

运行：先构建 Chromium 原生宿主，再设置 LOCKLARK_BROWSER_HOST 和 LOCKLARK_TEST_CHECKOUT_FRAMES=1，在可见 X11 会话执行 node scripts/browser_native_acceptance.mjs。输出仅含固定阶段；合成凭据、字段内容和原始诊断留在私有验收目录。
