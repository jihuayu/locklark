(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  let busy = false,
    renderedCandidates = "",
    renderedBanner = "",
    renderedWatchtower = "",
    lastState = null,
    actionGeneration = 0,
    requestSequence = 0,
    renderedSequence = 0,
    watchtowerCategory = "",
    hibpOptIn = false,
    hibpOptInPending = false,
    hibpNotice = "";
  const WT_FLAGS = [
    "empty",
    "common-pattern",
    "short",
    "low-variety",
    "weak",
    "reused",
    "unsecured-http",
    "totp-not-stored",
    "passkey-not-stored",
    "expiring-soon",
    "expired",
    "vulnerable",
  ];
  const WT_LABELS = {
    empty: "空密码",
    "common-pattern": "常见模式",
    short: "长度不足",
    "low-variety": "字符单一",
    weak: "弱密码",
    reused: "重复密码",
    "unsecured-http": "HTTP 不安全",
    "totp-not-stored": "未设 2FA",
    "passkey-not-stored": "未存 Passkey",
    "expiring-soon": "即将过期",
    expired: "已过期",
    vulnerable: "已泄露",
  };
  const CANDIDATE_BADGES = [
    "vulnerable",
    "weak",
    "reused",
    "unsecured-http",
    "totp-not-stored",
  ];
  const STRENGTH_LABELS = {
    terrible: "极弱",
    weak: "弱",
    fair: "一般",
    good: "良好",
    "very-good": "很强",
    excellent: "优秀",
    fantastic: "极佳",
  };
  const WATCHTOWER_CATEGORIES = [
    "vulnerable",
    "reused",
    "weak",
    "unsecured_http",
    "totp_not_stored",
    "expiring",
  ];
  function text(selector, value) {
    const el = document.querySelector(selector);
    if (el.textContent !== value) el.textContent = value;
  }
  function httpsOrigin(value) {
    if (typeof value !== "string" || value.length > 2048) return "";
    try {
      const u = new URL(value);
      return u.protocol === "https:" &&
        !u.username &&
        !u.password &&
        u.origin === value
        ? u.origin
        : "";
    } catch {
      return "";
    }
  }
  function safeFlags(record) {
    const source = Array.isArray(record?.watchtower_flags)
      ? record.watchtower_flags
      : Array.isArray(record?.flags)
        ? record.flags
        : [];
    return WT_FLAGS.filter((flag) => source.includes(flag));
  }
  function flagBadge(flag) {
    const badge = document.createElement("span");
    badge.className =
      "wt-badge " +
      (flag === "vulnerable"
        ? "wt-red"
        : ["weak", "reused", "unsecured-http"].includes(flag)
          ? "wt-amber"
          : "wt-neutral");
    badge.dataset.wtFlag = flag;
    badge.textContent = WT_LABELS[flag] || flag;
    return badge;
  }
  function currentOrigin(state) {
    if (state?.site && typeof state.site.origin === "string" && state.site.origin)
      return state.site.origin;
    if (typeof state?.origin === "string" && state.origin) return state.origin;
    if (
      state?.watchtower?.site &&
      typeof state.watchtower.site.origin === "string"
    )
      return state.watchtower.site.origin;
    return "";
  }
  function siteFindingFlags(state) {
    const origin = currentOrigin(state);
    const report = state?.watchtower;
    const flags = new Set();
    if (state?.site?.unsecured === true) flags.add("unsecured-http");
    for (const row of state?.candidates || [])
      for (const flag of safeFlags(row)) flags.add(flag);
    if (report && Array.isArray(report.site_findings)) {
      const all = report.site?.origin === origin;
      for (const finding of report.site_findings) {
        if (!all && origin && finding.origin !== origin) continue;
        for (const flag of safeFlags(finding)) flags.add(flag);
        if (
          Number.isSafeInteger(finding.breach_count) &&
          finding.breach_count > 0
        )
          flags.add("vulnerable");
      }
    }
    for (const row of state?.candidates || [])
      if (Number.isSafeInteger(row.breach_count) && row.breach_count > 0)
        flags.add("vulnerable");
    return flags;
  }
  function bannerModel(state) {
    const flags = siteFindingFlags(state);
    const origin = currentOrigin(state);
    const openable = httpsOrigin(origin);
    if (flags.has("vulnerable"))
      return {
        show: true,
        level: "critical",
        badge: "严重 · 密码已出现在公开泄露库",
        text: "当前网站保存的密码已出现在公开泄露库，请立即生成强密码并更新登录。",
        origin: openable,
      };
    if (flags.has("unsecured-http"))
      return {
        show: true,
        level: "warning",
        badge: "警告 · 不安全的 HTTP 网站",
        text: "当前网页使用不安全的 HTTP 连接，不建议在此输入密码。",
        origin: "",
      };
    if (flags.has("weak") || flags.has("reused"))
      return {
        show: true,
        level: "warning",
        badge: "警告 · 弱密码 / 重复使用密码",
        text: "当前网站保存的登录存在弱密码或重复使用的密码，建议生成并更新强密码。",
        origin: openable,
      };
    return { show: false, level: "", badge: "", text: "", origin: "" };
  }
  function renderSiteBanner(state) {
    const model = bannerModel(state);
    const signature = JSON.stringify({ model, busy });
    if (signature === renderedBanner) return;
    renderedBanner = signature;
    const banner = document.querySelector("#watchtower-site-banner");
    banner.hidden = !model.show;
    banner.dataset.level = model.level;
    text("#watchtower-site-badge", model.badge);
    text("#watchtower-site-text", model.text);
    const action = document.querySelector("#watchtower-site-action");
    action.hidden = !model.origin;
    action.disabled = busy || !model.origin;
    action.dataset.origin = model.origin;
  }
  function reportFindings(report) {
    if (!report) return [];
    if (Array.isArray(report.findings) && report.findings.length)
      return report.findings;
    return Array.isArray(report.site_findings) ? report.site_findings : [];
  }
  function matchesCategory(finding, category) {
    const flags = safeFlags(finding);
    if (category === "vulnerable") return flags.includes("vulnerable");
    if (category === "reused") return flags.includes("reused");
    if (category === "weak") return flags.includes("weak");
    if (category === "unsecured_http")
      return flags.includes("unsecured-http");
    if (category === "totp_not_stored")
      return flags.includes("totp-not-stored");
    if (category === "expiring")
      return flags.includes("expiring-soon") || flags.includes("expired");
    return true;
  }
  function strengthLevel(score) {
    return score >= 80 ? "green" : score >= 50 ? "amber" : "red";
  }
  function findingNode(finding) {
    const container = document.createElement("div");
    container.className = "wt-finding";
    if (typeof finding.id === "string") container.dataset.wtItemId = finding.id;
    const title = document.createElement("div");
    title.className = "wt-finding-title";
    title.textContent =
      typeof finding.title === "string" && finding.title
        ? finding.title
        : "（无标题）";
    const meta = document.createElement("div");
    meta.className = "note";
    const bits = [];
    if (typeof finding.origin === "string" && finding.origin)
      bits.push(finding.origin);
    const score = Number.isSafeInteger(finding.strength_score)
      ? Math.max(0, Math.min(100, finding.strength_score))
      : null;
    if (score !== null)
      bits.push(
        `强度 ${score}/100 · ${
          STRENGTH_LABELS[finding.strength_category] || "未知"
        }`,
      );
    if (
      Number.isSafeInteger(finding.reuse_count) &&
      finding.reuse_count > 1
    )
      bits.push(`重复使用 ${finding.reuse_count} 次`);
    if (
      Number.isSafeInteger(finding.breach_count) &&
      finding.breach_count > 0
    )
      bits.push(`泄露 ${finding.breach_count} 次`);
    meta.textContent = bits.join(" · ");
    const pills = document.createElement("div");
    for (const flag of safeFlags(finding)) pills.append(flagBadge(flag));
    const children = [title, meta];
    if (score !== null) {
      const bar = document.createElement("div");
      bar.className = "wt-strength";
      const fill = document.createElement("div");
      fill.style.width = `${score}%`;
      fill.dataset.level = strengthLevel(score);
      bar.append(fill);
      children.push(bar);
    }
    children.push(pills);
    const origin = httpsOrigin(finding.origin);
    if (origin) {
      const action = document.createElement("button");
      action.type = "button";
      action.dataset.action = "watchtower-open";
      action.dataset.origin = origin;
      action.textContent = "打开并修改";
      action.addEventListener("click", () =>
        void act({ type: "watchtower-open", origin }),
      );
      children.push(action);
    }
    container.append(...children);
    return container;
  }
  function renderWatchtowerPanel(state) {
    const optIn = document.querySelector("#watchtower-hibp-optin");
    const persisted = state.watchtowerHIBP === true;
    if (hibpOptInPending && persisted === hibpOptIn) hibpOptInPending = false;
    if (!hibpOptInPending) hibpOptIn = persisted;
    optIn.checked = hibpOptIn;
    const report =
      state.watchtower &&
      typeof state.watchtower === "object" &&
      !Array.isArray(state.watchtower)
        ? state.watchtower
        : null;
    const signature = JSON.stringify({
      report,
      hibpOptIn,
      category: watchtowerCategory,
      busy,
      connected: !!state.connected,
      pending: !!state.pending,
      notice: hibpNotice,
    });
    if (signature === renderedWatchtower) return;
    renderedWatchtower = signature;
    const score = Number.isSafeInteger(report?.overall_score)
      ? Math.max(0, Math.min(100, report.overall_score))
      : null;
    text("#watchtower-score", score === null ? "—" : `${score}/100`);
    const bar = document.querySelector("#watchtower-score-bar");
    bar.style.width = score === null ? "0%" : `${score}%`;
    bar.dataset.level = score === null ? "" : strengthLevel(score);
    const counts =
      report?.counts && typeof report.counts === "object" ? report.counts : {};
    for (const category of WATCHTOWER_CATEGORIES) {
      const count = Number.isSafeInteger(counts[category])
        ? Math.max(0, counts[category])
        : 0;
      text(`#watchtower-count-${category}`, String(count));
      const card = document.querySelector(`#watchtower-card-${category}`);
      card.dataset.active = watchtowerCategory === category ? "true" : "false";
    }
    const disabled = !state.connected || state.pending || busy;
    document.querySelector("#watchtower-refresh").disabled = disabled;
    document.querySelector("#watchtower-run-hibp").disabled = disabled;
    let summary = "";
    if (report) {
      const checked = Number.isSafeInteger(report.checked) ? report.checked : 0;
      summary = `已检查 ${checked} 项`;
      if (Number.isSafeInteger(report.skipped) && report.skipped > 0)
        summary += ` · 跳过 ${report.skipped} 项`;
      summary += report.hibp_checked
        ? " · 已包含 HIBP 检查"
        : " · 仅本地检查";
    }
    const findings = report
      ? reportFindings(report).filter(
          (finding) =>
            !watchtowerCategory ||
            matchesCategory(finding, watchtowerCategory),
        )
      : [];
    if (findings.length > 100) summary += " · 仅显示前 100 项";
    text("#watchtower-summary", summary);
    const empty = document.querySelector("#watchtower-empty");
    const emptyText = !report
      ? "尚未运行安全体检。点击“运行本地体检”离线检查当前金库。"
      : findings.length === 0
        ? watchtowerCategory
          ? "该分类下暂无项目。"
          : "未发现已知安全问题。"
        : "";
    empty.hidden = !emptyText;
    text("#watchtower-empty", emptyText);
    const list = document.querySelector("#watchtower-findings");
    list.replaceChildren(...findings.slice(0, 100).map(findingNode));
    const defaultNote =
      "本地检查完全离线；HIBP 仅在你勾选并点击“检查泄露库”时联网。";
    text(
      "#watchtower-hibp-note",
      hibpNotice ||
        (report?.hibp_error === "unavailable"
          ? "泄露库暂不可用，已显示本地体检结果。"
          : report?.hibp_checked
            ? "本次体检已包含 HIBP k-Anonymity 泄露库检查。"
            : defaultNote),
    );
  }
  function render(state) {
    lastState = state;
    document.querySelector("#auto-login").checked = state.autoLogin !== false;
    document.querySelector("#passkey-save").checked =
      state.offerSavePasskeys !== false;
    document.querySelector("#passkey-use").checked =
      state.offerUsePasskeys !== false;
    text("#status", state.status || "");
    text("#origin", state.origin || "");
    text(
      "#save-warning",
      state.saveBlocked
        ? "保存结果未确认。请先在原生金库核实；需要继续保存时，先断开并重新连接。"
        : "",
    );
    document.querySelector("#connect").disabled = state.connected || busy;
    document.querySelector("#refresh").disabled =
      !state.connected || state.pending || busy;
    document.querySelector("#save-new").disabled =
      !state.connected || state.pending || state.saveBlocked || busy;
    document.querySelector("#cancel-otp").disabled = !state.otpPending;
    renderSiteBanner(state);
    renderWatchtowerPanel(state);
    const list = document.querySelector("#candidates");
    const signature = JSON.stringify({
      rows: state.candidates || [],
      pending: state.pending,
      busy,
      saveBlocked: !!state.saveBlocked,
      loginOverrides: state.loginOverrides,
    });
    if (signature === renderedCandidates) return;
    renderedCandidates = signature;
    list.replaceChildren();
    for (const row of state.candidates || []) {
      const container = document.createElement("div");
      container.dataset.itemId = row.id;
      container.dataset.itemRevision = row.revision;
      const button = document.createElement("button");
      button.dataset.action = "fill";
      button.textContent = row.title || "（无标题）";
      button.disabled = state.pending || busy;
      button.addEventListener(
        "click",
        () => void act({ type: "fill", id: row.id, revision: row.revision }),
      );
      const update = document.createElement("button");
      update.dataset.action = "update";
      update.textContent = "更新此登录";
      update.disabled = state.pending || state.saveBlocked || busy;
      update.addEventListener(
        "click",
        () =>
          void act({
            type: "save-update",
            id: row.id,
            revision: row.revision,
          }),
      );
      const otp = document.createElement("button");
      otp.dataset.action = "otp";
      otp.textContent = "填充验证码";
      otp.disabled = state.pending || busy;
      otp.addEventListener(
        "click",
        () => void act({ type: "otp", id: row.id, revision: row.revision }),
      );
      const label = document.createElement("label"),
        toggle = document.createElement("input");
      toggle.type = "checkbox";
      toggle.disabled = state.pending || busy;
      toggle.checked = state.loginOverrides?.[row.id] !== false;
      toggle.addEventListener(
        "change",
        () =>
          void act({ type: "settings", id: row.id, enabled: toggle.checked }),
      );
      label.append(toggle, document.createTextNode(" 此登录允许自动提交"));
      container.append(button, update, otp, label);
      const rowFlags = safeFlags(row);
      for (const flag of CANDIDATE_BADGES)
        if (rowFlags.includes(flag)) container.append(flagBadge(flag));
      list.append(container);
    }
  }
  async function send(message, generation = actionGeneration) {
    const sequence = ++requestSequence;
    try {
      const state = await api.runtime.sendMessage(message);
      if (
        !state ||
        generation !== actionGeneration ||
        sequence <= renderedSequence
      )
        return;
      renderedSequence = sequence;
      render(state);
    } catch {
      if (generation !== actionGeneration || sequence <= renderedSequence)
        return;
      renderedSequence = sequence;
      render({
        connected: false,
        pending: false,
        candidates: [],
        origin: "",
        saveBlocked: !!lastState?.saveBlocked,
        status: "连接不可用，请重新打开弹窗",
      });
    }
  }
  async function act(message) {
    // Disconnect may interrupt a deferred action. Its generation also prevents
    // the old action's reply/finalizer from changing the next operation.
    if (busy && !["disconnect", "cancel-otp"].includes(message.type)) return;
    const generation = ++actionGeneration;
    busy = true;
    if (lastState) render(lastState);
    await send(message, generation);
    if (generation !== actionGeneration) return;
    await send({ type: "state" }, generation);
    if (generation !== actionGeneration) return;
    busy = false;
    if (lastState) render(lastState);
  }
  document
    .querySelector("#save-new")
    .addEventListener("click", () => void act({ type: "save-new" }));
  document
    .querySelector("#connect")
    .addEventListener("click", () => void act({ type: "connect" }));
  document
    .querySelector("#refresh")
    .addEventListener("click", () => void act({ type: "match" }));
  document
    .querySelector("#disconnect")
    .addEventListener("click", () => void act({ type: "disconnect" }));
  document
    .querySelector("#cancel-otp")
    .addEventListener("click", () => void act({ type: "cancel-otp" }));
  document
    .querySelector("#auto-login")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", autoLogin: event.target.checked }),
    );
  document
    .querySelector("#passkey-save")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", offerSavePasskeys: event.target.checked }),
    );
  document
    .querySelector("#passkey-use")
    .addEventListener(
      "change",
      (event) =>
        void act({ type: "settings", offerUsePasskeys: event.target.checked }),
    );
  document.querySelector("#watchtower-site-action").addEventListener(
    "click",
    () => {
      const origin = document.querySelector("#watchtower-site-action").dataset
        .origin;
      if (httpsOrigin(origin))
        void act({ type: "watchtower-open", origin });
    },
  );
  document
    .querySelector("#watchtower-refresh")
    .addEventListener("click", () => {
      hibpNotice = "";
      void act({ type: "watchtower", includeHibp: false });
    });
  document.querySelector("#watchtower-run-hibp").addEventListener("click", () => {
    if (!document.querySelector("#watchtower-hibp-optin").checked) {
      hibpNotice = "未启用 HIBP 检查：请先勾选上方选项。";
      renderedWatchtower = "";
      if (lastState) renderWatchtowerPanel(lastState);
      return;
    }
    hibpNotice = "";
    void act({ type: "watchtower", includeHibp: true });
  });
  document
    .querySelector("#watchtower-hibp-optin")
    .addEventListener("change", (event) => {
      hibpOptIn = event.target.checked;
      hibpOptInPending = true;
      hibpNotice = "";
      void act({ type: "settings", watchtowerHIBP: event.target.checked });
    });
  for (const category of WATCHTOWER_CATEGORIES)
    document
      .querySelector(`#watchtower-card-${category}`)
      .addEventListener("click", () => {
        watchtowerCategory = watchtowerCategory === category ? "" : category;
        renderedWatchtower = "";
        if (lastState) renderWatchtowerPanel(lastState);
      });
  void send({ type: "state" });
  setInterval(() => void send({ type: "state" }), 500);
})();
