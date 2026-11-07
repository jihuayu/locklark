(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  const core = globalThis.LocklarkCore || null;
  const vaultEnabled = document.body?.dataset?.vault === "1";
  let busy = false,
    renderedCandidates = "",
    renderedHistory = "",
    renderedBanner = "",
    renderedWatchtower = "",
    lastState = null,
    actionGeneration = 0,
    requestSequence = 0,
    renderedSequence = 0,
    generatorInitialized = false,
    connectionEpoch = 0,
    popupInactive = false,
    generatedPassword = "",
    generatedProfile = null,
    generatedDataWiped = false,
    generatorValues = { random: 24, memorable: 4, pin: 6 },
    watchtowerCategory = "",
    hibpOptIn = false,
    hibpOptInPending = false,
    hibpNotice = "";
  const query = (selector) => document.querySelector(selector);
  // Only an explicit generate reply may repopulate the preview while a
  // lock/hide-time wipe is still unconfirmed; generic state polls may not.
  const TRUSTED_GENERATED_SOURCES = new Set(["generate", "popup-generate"]);
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
    const el = query(selector);
    if (el.textContent !== value) el.textContent = value;
  }
  function clampInteger(value, min, max, fallback) {
    return Number.isSafeInteger(value)
      ? Math.min(max, Math.max(min, value))
      : fallback;
  }
  function generatorMode() {
    const value = query("#gen-mode").value;
    return ["random", "memorable", "pin"].includes(value) ? value : "random";
  }
  function generatorParams() {
    const mode = generatorMode();
    const raw = Number(query("#gen-length").value);
    if (mode === "random")
      return {
        mode,
        length: clampInteger(raw, 16, 64, generatorValues.random),
        digits: query("#gen-digits").checked,
        symbols: query("#gen-symbols").checked,
      };
    if (mode === "memorable")
      return {
        mode,
        length: clampInteger(raw, 3, 8, generatorValues.memorable),
        digits: false,
        capitalize: query("#gen-capitalize").checked,
        separator: query("#gen-separator").value || "hyphens",
      };
    return {
      mode,
      length: clampInteger(raw, 4, 12, generatorValues.pin),
    };
  }
  function initGenerator(state) {
    if (generatorInitialized) return;
    generatorInitialized = true;
    const defaults = state.generatorDefaults || {};
    query("#gen-mode").value = ["random", "memorable", "pin"].includes(
      defaults.mode,
    )
      ? defaults.mode
      : "random";
    generatorValues = {
      random: clampInteger(defaults.length, 16, 64, 24),
      memorable: clampInteger(defaults.wordCount, 3, 8, 4),
      pin: clampInteger(defaults.pinLength, 4, 12, 6),
    };
    query("#gen-digits").checked = defaults.digits !== false;
    query("#gen-symbols").checked = defaults.symbols !== false;
    query("#gen-capitalize").checked = defaults.capitalize !== false;
    query("#gen-separator").value =
      typeof defaults.separator === "string" && defaults.separator
        ? defaults.separator
        : "hyphens";
  }
  function applyGeneratorMode() {
    const mode = generatorMode();
    query("#gen-random-options").hidden = mode !== "random";
    query("#gen-memorable-options").hidden = mode !== "memorable";
    const range = query("#gen-length");
    range.min = String(mode === "random" ? 16 : mode === "pin" ? 4 : 3);
    range.max = String(mode === "random" ? 64 : mode === "pin" ? 12 : 8);
    range.value = String(generatorValues[mode]);
    query("#gen-length-value").textContent = String(generatorValues[mode]);
  }
  function applyGeneratedPreview(password, profile) {
    if (typeof password !== "string" || password.length < 4) return;
    generatedPassword = password;
    generatedProfile = profile && typeof profile === "object" ? profile : null;
    query("#gen-preview").textContent = password;
    query("#gen-entropy").textContent =
      String(profile?.entropy_bits_floor ?? "?") + " bits";
  }
  function clearGeneratedData() {
    // Single owner of "forget the generated password": drop the in-memory
    // reference, the live DOM copy (preview, entropy, history rows) and the
    // copy control, then scrub the cached state so a later render cannot
    // rehydrate the cleared values. Generic settings are untouched.
    generatedDataWiped = true;
    generatedPassword = "";
    generatedProfile = null;
    renderedHistory = "";
    const preview = query("#gen-preview");
    if (preview) preview.textContent = "";
    const entropy = query("#gen-entropy");
    if (entropy) entropy.textContent = "";
    const history = query("#gen-history");
    if (history) history.replaceChildren();
    const copy = query("#gen-copy");
    if (copy) copy.disabled = true;
    if (lastState && typeof lastState === "object")
      lastState = {
        ...lastState,
        password: "",
        profile: null,
        generatedHistory: [],
      };
  }
  function setGeneratorStatus(value) {
    const el = query("#gen-status");
    if (el) el.textContent = value;
  }
  function renderPending(state) {
    const pending =
      state.pendingSave && typeof state.pendingSave === "object"
        ? state.pendingSave
        : null;
    query("#pending-save-banner").hidden = !pending;
    if (!pending) {
      for (const selector of [
        "#commit-staged-save",
        "#dismiss-staged-save",
        "#never-save-origin",
      ])
        query(selector).disabled = true;
      return;
    }
    text(
      "#pending-save-mode",
      pending.mode === "update"
        ? "检测到待更新的登录密码"
        : "检测到待保存的新登录",
    );
    text("#pending-save-origin", pending.origin || state.origin || "");
    text(
      "#pending-save-username",
      "用户名：" + (pending.username || "（无用户名）"),
    );
    const title = query("#pending-save-title");
    if (document.activeElement !== title)
      title.value = pending.title || pending.origin || state.origin || "";
    query("#commit-staged-save").textContent =
      pending.mode === "update" ? "更新密码" : "保存登录";
    query("#commit-staged-save").disabled = busy;
    query("#dismiss-staged-save").disabled = busy;
    query("#never-save-origin").disabled = busy;
  }
  function renderGenerator(state) {
    initGenerator(state);
    applyGeneratorMode();
    if (
      typeof state.password === "string" &&
      state.password.length >= 4 &&
      state.profile
    )
      applyGeneratedPreview(state.password, state.profile);
    const pending = state.pending === true;
    for (const selector of [
      "#gen-mode",
      "#gen-length",
      "#gen-digits",
      "#gen-symbols",
      "#gen-capitalize",
      "#gen-separator",
    ])
      query(selector).disabled = busy || pending;
    query("#gen-regenerate").disabled = busy || pending;
    query("#gen-fill").disabled =
      busy || pending || state.connected !== true;
    query("#gen-copy").disabled = busy || !generatedPassword;
    query("#offer-save-logins").checked = state.offerSaveLogins !== false;
    query("#offer-save-logins").disabled = busy;
    const excluded = (state.neverSaveOrigins || []).includes(state.origin);
    const clear = query("#clear-never-save");
    clear.hidden = !excluded;
    clear.disabled = busy || state.connected !== true || !excluded;
  }
  function validHistoryEntry(entry) {
    return (
      entry &&
      typeof entry === "object" &&
      /^[a-f0-9]{32}$/.test(entry.id || "") &&
      typeof entry.password === "string" &&
      entry.password.length >= 4 &&
      entry.password.length <= 256 &&
      typeof entry.origin === "string"
    );
  }
  function renderHistory(state) {
    const entries = (Array.isArray(state.generatedHistory)
      ? state.generatedHistory
      : []
    ).filter(validHistoryEntry);
    const signature = JSON.stringify({
      entries: entries.map((entry) => [
        entry.id,
        entry.origin,
        entry.username,
        entry.password,
        entry.profile?.mode,
      ]),
      busy,
      pending: state.pending === true,
      connected: state.connected === true,
    });
    if (signature === renderedHistory) return;
    renderedHistory = signature;
    const list = query("#gen-history");
    list.replaceChildren();
    for (const entry of entries) {
      const row = document.createElement("div");
      row.dataset.entryId = entry.id;
      const label = document.createElement("p");
      label.textContent =
        (entry.origin || "未知网站") +
        " · " +
        (entry.username || "（无用户名）") +
        (entry.profile?.mode ? " · " + entry.profile.mode : "");
      const password = document.createElement("code");
      password.className = "mono";
      password.textContent = entry.password;
      const actions = document.createElement("div");
      actions.className = "actions";
      const fill = document.createElement("button");
      fill.type = "button";
      fill.dataset.action = "fill";
      fill.textContent = "填充";
      fill.disabled =
        busy || state.pending === true || state.connected !== true;
      fill.addEventListener("click", () => {
        if (!fill.disabled)
          void act({ type: "generator-history-fill", historyId: entry.id });
      });
      const save = document.createElement("button");
      save.type = "button";
      save.dataset.action = "save";
      save.textContent = "保存";
      save.disabled =
        busy || state.pending === true || state.connected !== true;
      save.addEventListener("click", () => {
        if (!save.disabled)
          void act({ type: "generator-history-save", historyId: entry.id });
      });
      actions.append(fill, save);
      row.append(label, password, actions);
      list.append(row);
    }
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
  function render(state, sourceType) {
    if (
      state.connected === false &&
      (attachmentBusy || attachmentTransfer || blobURLs.size)
    )
      clearAttachmentBuffers();
    const transitionedDisconnected =
      state.connected === false && lastState?.connected === true;
    if (transitionedDisconnected || generatedDataWiped)
      state = {
        ...state,
        // A trusted generate reply may keep only its own NEW password/profile;
        // history cached in the background before the wipe must never come
        // back, and a stale poll may not repopulate anything at all.
        ...(transitionedDisconnected ||
        !TRUSTED_GENERATED_SOURCES.has(sourceType)
          ? { password: "", profile: null }
          : {}),
        generatedHistory: [],
      };
    if (transitionedDisconnected) {
      connectionEpoch++;
      clearGeneratedData();
    }
    if (state.connected === false) generatedDataWiped = false;
    lastState = state;
    if (
      vaultEnabled &&
      document.body?.dataset?.view === "detail" &&
      lastDetail
    )
      renderPasskeyDetail(lastDetail);
    query("#auto-login").checked = state.autoLogin !== false;
    query("#passkey-save").checked = state.offerSavePasskeys !== false;
    query("#passkey-use").checked = state.offerUsePasskeys !== false;
    text("#status", state.status);
    text("#origin", state.origin);
    text(
      "#save-warning",
      state.saveBlocked
        ? "保存结果未确认。请先在原生金库核实；需要继续保存时，先断开并重新连接。"
        : "",
    );
    query("#connect").disabled = state.connected || busy;
    query("#refresh").disabled =
      !state.connected || state.pending || busy;
    query("#save-new").disabled =
      !state.connected || state.pending || state.saveBlocked || busy;
    query("#cancel-otp").disabled = !state.otpPending;
    renderPending(state);
    renderGenerator(state);
    renderHistory(state);
    renderSiteBanner(state);
    renderWatchtowerPanel(state);
    // Vault lifecycle must run even when website candidates are unchanged.
    if (vaultEnabled) renderVault(state);
    const list = query("#candidates");
    const signature = JSON.stringify({
      rows: state.candidates || [],
      connected: state.connected,
      pending: state.pending,
      busy,
      saveBlocked: !!state.saveBlocked,
      loginOverrides: state.loginOverrides,
    });
    if (signature === renderedCandidates) return;
    renderedCandidates = signature;
    list.replaceChildren();
    for (const row of state.candidates || []) {
      const category = row.category || "login";
      const container = document.createElement("div");
      container.dataset.itemId = row.id;
      container.dataset.itemRevision = row.revision;
      container.dataset.itemCategory = category;
      const button = document.createElement("button");
      button.dataset.action = "fill";
      button.textContent =
        (category === "identity"
          ? "身份 · "
          : category === "credit_card"
            ? "信用卡 · "
            : "") +
        (row.title || "（无标题）") +
        (row.subtitle ? " · " + row.subtitle : "");
      button.disabled = state.pending || busy;
      button.addEventListener("click", () =>
        void act({
          type: "fill",
          id: row.id,
          revision: row.revision,
          ...(category === "login" ? {} : { category }),
        }),
      );
      if (category !== "login") {
        container.append(button);
        list.append(container);
        continue;
      }
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
    const epoch = connectionEpoch;
    try {
      const state = await api.runtime.sendMessage(message);
      if (
        !state ||
        popupInactive || epoch !== connectionEpoch ||
        generation !== actionGeneration ||
        sequence <= renderedSequence
      )
        return null;
      renderedSequence = sequence;
      render(state, message?.type);
      return state;
    } catch {
      if (popupInactive || epoch !== connectionEpoch || generation !== actionGeneration || sequence <= renderedSequence)
        return null;
      renderedSequence = sequence;
      render({
        connected: false,
        pending: false,
        candidates: [],
        origin: "",
        saveBlocked: !!lastState?.saveBlocked,
        status: "连接不可用，请重新打开弹窗",
      });
      return null;
    }
  }
  async function act(message) {
    // Disconnect may interrupt a deferred action. Its generation also prevents
    // the old action's reply/finalizer from changing the next operation.
    if (busy && !["disconnect", "cancel-otp"].includes(message.type)) return;
    if (["disconnect", "lock"].includes(message.type)) {
      cancelPasskeyRemoval();
      // Clear before the host round trip: the lock reply may be deferred and a
      // copyable cached password must not survive the intent to lock.
      clearGeneratedData();
    }
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
  function regenerate() {
    setGeneratorStatus("正在生成…");
    void act({
      type: "generate",
      recordHistory: false,
      ...generatorParams(),
    });
  }
  async function copyGenerated() {
    if (!generatedPassword) return;
    // A hidden or restored popup must not write a clipboard value it no longer
    // shows; offline generation stays allowed because it copies the preview.
    if (popupInactive || document.visibilityState === "hidden") return;
    let copied = false;
    try {
      const clipboard = globalThis.navigator?.clipboard;
      if (!clipboard || typeof clipboard.writeText !== "function")
        throw Error("clipboard unavailable");
      await clipboard.writeText(generatedPassword);
      copied = true;
    } catch {}
    setGeneratorStatus(copied ? "已复制" : "复制失败");
  }

  /* ------------------------------------------------------------------ *
   * Vault UI. The legacy candidate list above stays authoritative for  *
   * native fill/update/OTP acceptance; the vault pane adds browse,     *
   * search, detail, copy, Open & Fill and item editing.                *
   * ------------------------------------------------------------------ */
  const CATEGORY_LABELS = {
    login: "登录",
    password: "密码",
    note: "安全备注",
    secure_note: "安全备注",
    identity: "身份信息",
    card: "银行卡",
    credit_card: "银行卡",
    ssh: "SSH 密钥",
  };
  const FILTER_LABELS = {
    suggested: "当前网站",
    all: "全部",
    favorites: "收藏",
    passkeys: "Passkey",
    login: "登录",
    identity: "身份",
    credit_card: "银行卡",
    secure_note: "安全备注",
  };
  const EDITOR_TEMPLATES = {
    login: [
      { name: "title", label: "标题", type: "text", required: true },
      { name: "username", label: "用户名", type: "text" },
      { name: "password", label: "密码", type: "password", generate: true },
      { name: "otp_secret", label: "一次性验证码密钥（可选）", type: "text" },
      { name: "urls", label: "网站（每行一个 HTTPS 地址）", type: "textarea" },
      { name: "notes", label: "备注", type: "textarea" },
      { name: "tags", label: "标签（逗号分隔）", type: "text" },
      { name: "favorite", label: "收藏此条目", type: "checkbox" },
    ],
    password: [
      { name: "title", label: "标题", type: "text", required: true },
      { name: "password", label: "密码", type: "password", generate: true },
      { name: "urls", label: "网站（每行一个 HTTPS 地址）", type: "textarea" },
      { name: "notes", label: "备注", type: "textarea" },
      { name: "tags", label: "标签（逗号分隔）", type: "text" },
      { name: "favorite", label: "收藏此条目", type: "checkbox" },
    ],
    note: [
      { name: "title", label: "标题", type: "text", required: true },
      { name: "content", label: "备注内容", type: "textarea" },
      { name: "tags", label: "标签（逗号分隔）", type: "text" },
      { name: "favorite", label: "收藏此条目", type: "checkbox" },
    ],
    identity: [
      { name: "title", label: "标题", type: "text", required: true },
      { name: "first_name", label: "名", type: "text" },
      { name: "last_name", label: "姓", type: "text" },
      { name: "email", label: "邮箱", type: "email" },
      { name: "phone", label: "电话", type: "tel" },
      { name: "organization", label: "公司", type: "text" },
      { name: "address1", label: "地址第一行", type: "text" },
      { name: "address2", label: "地址第二行", type: "text" },
      { name: "city", label: "城市", type: "text" },
      { name: "state", label: "省/州", type: "text" },
      { name: "postal_code", label: "邮政编码", type: "text" },
      { name: "country", label: "国家/地区", type: "text" },
      { name: "notes", label: "备注", type: "textarea" },
      { name: "tags", label: "标签（逗号分隔）", type: "text" },
      { name: "favorite", label: "收藏此条目", type: "checkbox" },
    ],
    card: [
      { name: "title", label: "标题", type: "text", required: true },
      { name: "cardholder", label: "持卡人姓名", type: "text" },
      {
        name: "brand",
        label: "卡组织（Visa/Mastercard/Amex/UnionPay/Other）",
        type: "text",
      },
      { name: "card_number", label: "卡号", type: "password" },
      { name: "expiry", label: "有效期（MM/YY）", type: "text" },
      { name: "cvv", label: "安全码", type: "password" },
      { name: "billing_postal_code", label: "账单邮编", type: "text" },
      { name: "notes", label: "备注", type: "textarea" },
      { name: "tags", label: "标签（逗号分隔）", type: "text" },
      { name: "favorite", label: "收藏此条目", type: "checkbox" },
    ],
  };
  let searchQuery = "",
    activeFilter = "suggested",
    vaultLoaded = false,
    vaultBusy = false,
    vaultOperation = 0,
    vaultItems = [],
    renderedVault = "",
    secretGeneration = 0,
    editorGeneration = 0,
    lastDetail = null,
    revealedSecrets = new Map(),
    revealTimers = new Map(),
    pendingReveals = new Map(),
    editorMode = "",
    editorCategory = "",
    editorValues = null,
    editorInputs = [],
    searchTimer = null,
    toastTimer = null,
    clipboardTimer = null,
    feedbackTimer = null,
    editorHadSections = false,
    editorConflict = "",
    vaultQueryGeneration = 0,
    passkeyDetailGeneration = 0,
    detailReadOperation = 0,
    passkeyRemoveGeneration = 0,
    passkeyConfirm = null,
    passkeyRemoving = false,
    passkeyUncertain = null,
    passkeyStatusText = "",
    attachmentGeneration = 0,
    attachmentBusy = false,
    attachmentTransfer = "",
    attachmentCancelled = false,
    attachmentCommitting = false,
    blobURLs = new Set(),
    els = null;

  function q(selector) {
    return document.querySelector(selector);
  }
  function all(selector) {
    return document.querySelectorAll
      ? [...document.querySelectorAll(selector)]
      : [];
  }
  function beginVaultOperation() {
    vaultBusy = true;
    return ++vaultOperation;
  }
  function finishVaultOperation(operation) {
    if (operation !== vaultOperation) return false;
    vaultBusy = false;
    return true;
  }
  function toast(message) {
    if (!els?.toast) return;
    els.toast.textContent = message;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastTimer = null;
      if (els?.toast) els.toast.textContent = "";
    }, 2500);
  }
  function showView(name) {
    if (name !== "detail") cancelPasskeyRemoval();
    if (name !== "detail") clearRevealedSecrets();
    if (!els) return;
    els.vaultView.hidden = name !== "vault";
    els.detailView.hidden = name !== "detail";
    els.editorView.hidden = name !== "editor";
    document.body.dataset.view = name;
  }
  function wipeDetail() {
    cancelPasskeyRemoval();
    passkeyDetailGeneration++;
    if (els?.passkeyDetail) els.passkeyDetail.hidden = true;
    clearAttachmentBuffers();
    if (els?.detailFields) els.detailFields.replaceChildren();
    if (els) {
      els.detailTitle.textContent = "";
      els.detailNotes.textContent = "";
      els.detailUrls.replaceChildren();
      els.detailTags.replaceChildren();
      els.detailUpdated.textContent = "";
      els.detailUnavailable.textContent = "";
      els.detailUnavailable.hidden = true;
    }
    lastDetail = null;
    clearRevealedSecrets();
  }
  function wipeEditor() {
    editorGeneration++;
    for (const input of editorInputs) {
      if ("value" in input) input.value = "";
      if (input.type === "checkbox") input.checked = false;
    }
    editorInputs = [];
    if (els?.editorFields) els.editorFields.replaceChildren();
    if (els?.customFields) els.customFields.replaceChildren();
    editorValues = null;
    editorMode = "";
    editorCategory = "";
    editorHadSections = false;
    editorConflict = "";
  }
  function wipeSensitiveViews() {
    vaultQueryGeneration++;
    vaultOperation++;
    vaultBusy = false;
    // The invalidated query's finalizer skips re-enabling the box, so the
    // owner that bumped the generation must restore it here.
    if (els?.searchInput) els.searchInput.disabled = false;
    if (els?.editorSave) els.editorSave.disabled = false;
    wipeDetail();
    wipeEditor();
    if (els) showView("vault");
  }
  function categoryLabel(category) {
    return CATEGORY_LABELS[category] || "条目";
  }
  function stateItems() {
    if (activeFilter === "passkeys")
      return Array.isArray(vaultItems) ? vaultItems : [];
    if (Array.isArray(lastState?.vaultItems) && lastState.vaultItems.length)
      return lastState.vaultItems;
    if (!Array.isArray(lastState?.candidates)) return [];
    const origin = lastState.origin || "";
    return lastState.candidates.map((row) => ({
      id: row.id,
      revision: row.revision,
      category: "login",
      title: row.title || "",
      subtitle: "",
      urls: origin ? [origin] : [],
      tags: [],
      favorite: false,
      state: "active",
      has_otp: false,
      updated_at: "",
    }));
  }
  function filteredItems() {
    const items = stateItems();
    // Passkey rows are already filtered by the native host before its 500-row
    // cap; filtering this truncated page again would hide valid matches.
    if (activeFilter === "passkeys") return items;
    if (!core) return items;
    return core.filterVaultItems(items, {
      query: searchQuery,
      category: activeFilter,
      origin: lastState?.origin || "",
    });
  }
  function renderLockedView(state) {
    if (!els) return;
    els.lockedView.hidden = !!state.connected;
    els.lockButton.disabled = !state.connected;
    if (state.connected && document.body.dataset.view === "locked")
      showView("vault");
    els.vaultView.hidden =
      state.connected === false || document.body.dataset.view !== "vault";
    if (state.connected === false) {
      els.vaultView.hidden = true;
      if (document.body.dataset.view !== "editor") showView("vault");
      els.vaultView.hidden = true;
    }
    if (els.siteDisableInline)
      els.siteDisableInline.checked = state.disabledInline === true;
    if (els.siteNeverSave)
      els.siteNeverSave.checked = state.neverSave === true;
  }
  function renderVaultList() {
    if (!els) return;
    const list = els.vaultList;
    const fieldLabels = fields => Array.isArray(fields) ? fields.slice(0, 100).map(
      field => field && [field.id, field.label, field.type, field.section_id],
    ) : [];
    // Compare bounded public inputs before URL matching, search and sorting.
    // Never retain item details, field values, or a decrypted snapshot.
    const signature = JSON.stringify([activeFilter, searchQuery, lastState?.origin,
      lastState?.passkeyManagementSupported, lastState?.passkeysUnsupported,
      stateItems().slice(0, 500).map(item => [item.id, item.revision, item.category,
        item.title, item.subtitle, item.username, item.favorite, item.tags, item.urls,
        fieldLabels(item.fields), fieldLabels(item.custom_fields),
        Array.isArray(item.sections) ? item.sections.slice(0, 20).map(section =>
          section && [section.id, section.title, fieldLabels(section.fields)]) : [],
        core?.validPasskeyMetadata?.(item.passkey) ? [
          item.passkey.credential_id, item.passkey.rp_id,
          item.passkey.user_name, item.passkey.display_name] : null])]);
    if (signature === renderedVault) return;
    renderedVault = signature;
    const items = filteredItems();
    const focusedID = document.activeElement?.dataset?.itemId;
    const scrollTop = list.scrollTop;
    list.replaceChildren();
    for (const item of items) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "vault-item";
      row.dataset.itemId = item.id;
      row.dataset.itemRevision = item.revision;
      row.dataset.category = core?.normalizeCategory(item.category) || "login";
      const title = document.createElement("span");
      title.className = "vault-item-title";
      title.textContent = item.title || "（无标题）";
      const passkey = core?.validPasskeyMetadata?.(item.passkey)
        ? item.passkey
        : null;
      const subtitle = document.createElement("span");
      subtitle.className = "vault-item-subtitle";
      subtitle.textContent = passkey
        ? passkey.user_name + " · " + passkey.rp_id
        : item.subtitle || item.username || "";
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = passkey
        ? "Passkey · " + categoryLabel(item.category)
        : categoryLabel(item.category);
      row.append(title, subtitle, badge);
      if (item.favorite === true) {
        const star = document.createElement("span");
        star.className = "favorite-mark";
        star.textContent = "★";
        row.prepend(star);
      }
      row.addEventListener("click", () => void openDetail(item));
      list.append(row);
    }
    list.scrollTop = scrollTop;
    if (focusedID) {
      const retained = [...list.children].find(row => row.dataset.itemId === focusedID);
      retained?.focus?.({ preventScroll: true });
    }
    const passkeysUnsupported =
      activeFilter === "passkeys" &&
      (lastState?.passkeyManagementSupported === false ||
        lastState?.passkeysUnsupported === true);
    if (els.passkeyUnsupported) {
      els.passkeyUnsupported.hidden = !passkeysUnsupported;
      els.passkeyUnsupported.textContent = passkeysUnsupported
        ? "当前原生宿主不支持 Passkey 管理，请升级原生宿主后再试；未显示本地筛选的不完整结果。"
        : "";
    }
    els.vaultCount.textContent = `${items.length} 个${
      activeFilter === "passkeys" ? " Passkey" : "条目"
    } · ${FILTER_LABELS[activeFilter] || "全部"}`;
    els.vaultEmpty.hidden = items.length !== 0 || passkeysUnsupported;
    els.vaultEmpty.textContent =
      activeFilter === "passkeys"
        ? "没有找到 Passkey"
        : activeFilter === "favorites"
        ? "暂无收藏条目"
        : activeFilter === "suggested"
          ? "当前网站无匹配条目"
          : searchQuery
            ? "没有匹配的条目"
            : "金库中暂无条目";
    for (const tab of all("#filter-tabs [data-filter]")) {
      tab.setAttribute("tabindex", tab.dataset.filter === activeFilter ? "0" : "-1");
      tab.setAttribute(
        "aria-selected",
        tab.dataset.filter === activeFilter ? "true" : "false",
      );
      tab.classList.toggle(
        "active",
        tab.dataset.filter === activeFilter,
      );
    }
  }
  function renderVault(state) {
    if (!els) return;
    if (!state.connected) {
      vaultLoaded = false;
      vaultItems = [];
      renderedVault = "";
      els.vaultList.replaceChildren();
      wipeSensitiveViews();
    } else if (
      Array.isArray(state.vaultItems) &&
      (state.vaultItems.length || activeFilter === "passkeys")
    ) {
      vaultItems = state.vaultItems;
      vaultLoaded = true;
    }
    renderLockedView(state);
    if (state.connected === false) return;
    renderVaultList();
    if (!vaultLoaded && !vaultBusy && document.body.dataset.view === "vault") {
      vaultLoaded = true;
      void refreshVault(true);
    }
  }
  function vaultFilterState() {
    return {
      query: searchQuery,
      category: activeFilter,
      passkeysOnly: activeFilter === "passkeys",
    };
  }
  function sameVaultFilter(a, b) {
    return (
      !!a &&
      !!b &&
      a.query === b.query &&
      a.category === b.category &&
      a.passkeysOnly === b.passkeysOnly
    );
  }
  async function refreshVault(silent = false) {
    if (!vaultEnabled || !lastState?.connected) return;
    const generation = ++vaultQueryGeneration;
    const filters = vaultFilterState();
    if (els?.searchInput) els.searchInput.disabled = true;
    const isCurrent = () =>
      !popupInactive && lastState?.connected === true &&
      generation === vaultQueryGeneration &&
      sameVaultFilter(filters, vaultFilterState());
    try {
      const reply = await api.runtime.sendMessage({
        type: "vault-search",
        query: filters.query,
        category: filters.category,
        passkeysOnly: filters.passkeysOnly,
      });
      if (!isCurrent()) return;
      if (reply && typeof reply === "object") {
        if (
          reply.status ||
          typeof reply.connected === "boolean" ||
          typeof reply.passkeyManagementSupported === "boolean" ||
          reply.vaultSource ||
          reply.passkeysUnsupported !== undefined
        )
          lastState = { ...lastState, ...reply };
        if (Array.isArray(reply.vaultItems)) vaultItems = reply.vaultItems;
        if (reply.passkeysUnsupported === true) vaultItems = [];
        vaultLoaded = true;
        renderVaultList();
      }
    } catch {
      if (!isCurrent()) return;
      if (!silent) toast("无法读取金库条目");
    } finally {
      if (generation === vaultQueryGeneration) {
        if (els?.searchInput) els.searchInput.disabled = false;
        renderLockedView(lastState || {});
      }
    }
  }
  function scheduleVaultSearch() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      searchTimer = null;
      void refreshVault(true);
    }, 120);
  }
  async function openDetail(item) {
    if (!item || vaultBusy || !lastState?.connected || popupInactive) return;
    const generation = ++passkeyDetailGeneration;
    cancelPasskeyRemoval({ clearUncertain: false });
    const operation = beginVaultOperation();
    detailReadOperation = operation;
    try {
      const reply = await api.runtime.sendMessage({
        type: "item-get",
        id: item.id,
        revision: item.revision,
      });
      if (!reply?.detail) throw Error("refused");
      if (generation !== passkeyDetailGeneration || !lastState?.connected || popupInactive) return;
      if (typeof reply.connected === "boolean")
        lastState = { ...lastState, ...reply };
      passkeyUncertain = null;
      lastDetail = reply.detail;
      clearRevealedSecrets();
      renderDetail(reply.detail);
      showView("detail");
    } catch {
      toast("无法读取条目详情");
    } finally {
      if (detailReadOperation === operation) detailReadOperation = 0;
      finishVaultOperation(operation);
    }
  }
  function detailFields(detail) {
    const fields = core ? core.flattenItemFields(detail) : [];
    if (!fields.some((field) => field.id === "username") && detail.username)
      fields.unshift({
        id: "username",
        label: "用户名",
        type: "text",
        value: detail.username,
        concealed: false,
      });
    if (
      !fields.some((field) => field.id === "password") &&
      (detail.has_password === true || detail.password)
    )
      fields.push({
        id: "password",
        label: "密码",
        type: "concealed",
        value: detail.password || "",
        concealed: true,
        has_value: true,
        revealable: true,
      });
    if (
      !fields.some((field) => field.id === "otp") &&
      (detail.has_otp === true || detail.otp_code || detail.otp_secret)
    )
      fields.push({
        id: "otp",
        label: "一次性验证码",
        type: "totp",
        value: detail.otp_code || "",
        concealed: false,
        has_value: true,
        revealable: true,
      });
    return fields;
  }
  function passkeyTargetFrom(detail) {
    const passkey = detail?.passkey;
    if (!detail || !core?.validPasskeyMetadata?.(passkey)) return null;
    if (
      !/^[a-f0-9]{32}$/.test(detail.id || "") ||
      !/^[a-f0-9]{64}$/.test(detail.revision || "")
    )
      return null;
    return {
      itemId: detail.id,
      revision: detail.revision,
      credentialId: passkey.credential_id,
      detailGeneration: passkeyDetailGeneration,
    };
  }
  function samePasskeyTarget(a, b) {
    return (
      !!a &&
      !!b &&
      a.itemId === b.itemId &&
      a.revision === b.revision &&
      a.credentialId === b.credentialId
    );
  }
  function cancelPasskeyRemoval(options = {}) {
    passkeyRemoveGeneration++;
    passkeyConfirm = null;
    passkeyRemoving = false;
    if (options.clearUncertain !== false) passkeyUncertain = null;
    if (options.keepStatus !== true) passkeyStatusText = "";
    if (!els) return;
    if (els.passkeyRemoveConfirm) els.passkeyRemoveConfirm.hidden = true;
    if (els.passkeyRemoveCancel) els.passkeyRemoveCancel.hidden = true;
    if (els.passkeyRemoveWarning) els.passkeyRemoveWarning.hidden = true;
    if (els.passkeyStatus) els.passkeyStatus.textContent = passkeyStatusText;
  }
  function renderPasskeyDetail(detail) {
    if (!els?.passkeyDetail) return;
    const passkey = core?.validPasskeyMetadata?.(detail?.passkey)
      ? {
          credential_id: detail.passkey.credential_id,
          rp_id: detail.passkey.rp_id,
          user_name: detail.passkey.user_name,
          display_name: detail.passkey.display_name,
        }
      : null;
    const shouldShow = !!passkey || detail?.has_passkey === true;
    els.passkeyDetail.hidden = !shouldShow;
    if (!shouldShow) {
      if (passkeyConfirm) cancelPasskeyRemoval({ keepStatus: true });
      for (const key of ["passkeyRp", "passkeyUsername", "passkeyDisplayName"])
        if (els[key]) els[key].textContent = "";
      if (els.passkeyDetailUnsupported) els.passkeyDetailUnsupported.hidden = true;
      return;
    }
    const target = passkeyTargetFrom(detail);
    const supported = lastState?.passkeyManagementSupported === true;
    if (
      passkeyConfirm &&
      (!target || !samePasskeyTarget(passkeyConfirm, target) || !supported)
    )
      cancelPasskeyRemoval({ keepStatus: true });
    const uncertain =
      !!target &&
      !!passkeyUncertain &&
      samePasskeyTarget(passkeyUncertain, target) &&
      passkeyUncertain.detailGeneration === passkeyDetailGeneration;
    if (els.passkeyRp) els.passkeyRp.textContent = passkey?.rp_id || "-";
    if (els.passkeyUsername)
      els.passkeyUsername.textContent = passkey?.user_name || "-";
    if (els.passkeyDisplayName)
      els.passkeyDisplayName.textContent = passkey?.display_name || "-";
    if (els.passkeyDetailUnsupported) {
      els.passkeyDetailUnsupported.hidden = supported && !!passkey;
      els.passkeyDetailUnsupported.textContent = !supported
        ? "当前原生宿主不支持 Passkey 管理，请升级原生宿主后再试。"
        : !passkey
          ? "当前原生宿主未提供可安全显示的 Passkey 元数据，请刷新或升级原生宿主。"
          : "";
    }
    const confirming = !!passkeyConfirm;
    if (els.passkeyRemove) {
      els.passkeyRemove.hidden =
        !passkey || !supported || confirming || uncertain;
      els.passkeyRemove.disabled =
        passkeyRemoving || uncertain || detail.readOnly === true;
    }
    if (els.passkeyRemoveConfirm) els.passkeyRemoveConfirm.hidden = !confirming;
    if (els.passkeyRemoveCancel) els.passkeyRemoveCancel.hidden = !confirming;
    if (els.passkeyRemoveWarning) els.passkeyRemoveWarning.hidden = !confirming;
    if (els.passkeyStatus)
      els.passkeyStatus.textContent = passkeyRemoving
        ? "正在删除 Passkey…"
        : passkeyStatusText;
  }
  function requestPasskeyRemovalConfirmation() {
    const target = passkeyTargetFrom(lastDetail);
    if (!target) return;
    if (
      passkeyUncertain &&
      samePasskeyTarget(passkeyUncertain, target) &&
      passkeyUncertain.detailGeneration === passkeyDetailGeneration
    ) {
      passkeyStatusText = "Passkey 删除结果未确认，请刷新核实";
      renderPasskeyDetail(lastDetail);
      return;
    }
    if (lastState?.passkeyManagementSupported !== true) {
      passkeyStatusText = "当前原生宿主不支持 Passkey 管理，请升级原生宿主";
      renderPasskeyDetail(lastDetail);
      return;
    }
    passkeyConfirm = target;
    passkeyStatusText = "";
    renderPasskeyDetail(lastDetail);
  }
  async function confirmPasskeyRemoval() {
    const target = passkeyTargetFrom(lastDetail);
    const confirmation = passkeyConfirm;
    if (
      !target ||
      !confirmation ||
      !samePasskeyTarget(target, confirmation) ||
      confirmation.detailGeneration !== passkeyDetailGeneration ||
      lastState?.passkeyManagementSupported !== true
    ) {
      cancelPasskeyRemoval();
      renderPasskeyDetail(lastDetail);
      toast("Passkey 删除确认已失效，请重新确认");
      return;
    }
    if (
      passkeyUncertain &&
      samePasskeyTarget(passkeyUncertain, target) &&
      passkeyUncertain.detailGeneration === passkeyDetailGeneration
    ) {
      passkeyStatusText = "Passkey 删除结果未确认，请刷新核实";
      renderPasskeyDetail(lastDetail);
      return;
    }
    if (passkeyRemoving) return;
    const operation = ++passkeyRemoveGeneration;
    const captured = { ...target };
    passkeyConfirm = null;
    passkeyRemoving = true;
    passkeyStatusText = "正在删除 Passkey…";
    renderPasskeyDetail(lastDetail);
    let reply = null;
    try {
      reply = await api.runtime.sendMessage({
        type: "passkey-remove",
        id: captured.itemId,
        revision: captured.revision,
        credential_id: captured.credentialId,
      });
    } catch {}
    if (operation !== passkeyRemoveGeneration) return;
    passkeyRemoving = false;
    if (
      !reply ||
      reply.passkeyRemoveError === "uncertain" ||
      (!reply.passkeyRemoved && reply.passkeyRemoveError !== "refused")
    ) {
      passkeyUncertain = {
        ...captured,
        detailGeneration: passkeyDetailGeneration,
      };
      passkeyStatusText = "Passkey 删除结果未确认，请刷新核实";
      renderPasskeyDetail(lastDetail);
      toast("Passkey 删除结果未确认，请刷新核实");
      return;
    }
    if (!reply.passkeyRemoved || reply.passkeyRemoveError === "refused") {
      passkeyStatusText = "Passkey 删除被拒绝";
      renderPasskeyDetail(lastDetail);
      return;
    }
    const removed = reply.passkeyRemoved;
    if (
      removed.item_id !== captured.itemId ||
      removed.credential_id !== captured.credentialId ||
      !/^[a-f0-9]{64}$/.test(removed.revision || "")
    ) {
      passkeyUncertain = {
        ...captured,
        detailGeneration: passkeyDetailGeneration,
      };
      passkeyStatusText = "Passkey 删除结果未确认，请刷新核实";
      renderPasskeyDetail(lastDetail);
      toast("Passkey 删除结果未确认，请刷新核实");
      return;
    }
    passkeyUncertain = null;
    lastState = { ...lastState, ...reply };
    vaultItems = [];
    vaultLoaded = false;
    if (lastDetail?.id === captured.itemId) {
      const { passkey, ...rest } = lastDetail;
      lastDetail = { ...rest, revision: removed.revision, has_passkey: false };
    }
    passkeyDetailGeneration++;
    passkeyStatusText = "Passkey 已删除；此登录和其他信息仍保留";
    renderPasskeyDetail(lastDetail);
    await refreshVault(true);
    if (operation !== passkeyRemoveGeneration) return;
    try {
      const refreshed = await api.runtime.sendMessage({
        type: "item-get",
        id: captured.itemId,
        revision: removed.revision,
      });
      if (
        operation !== passkeyRemoveGeneration ||
        document.body?.dataset?.view !== "detail"
      )
        return;
      if (refreshed?.detail) {
        lastState = { ...lastState, ...refreshed };
        lastDetail = refreshed.detail;
        passkeyStatusText = "Passkey 已删除；此登录和其他信息仍保留";
        renderDetail(lastDetail);
      }
    } catch {}
  }
  function renderDetail(detail) {
    if (!els || !detail) return;
    els.detailTitle.textContent = detail.title || "（无标题）";
    els.detailCategory.textContent = categoryLabel(detail.category);
    els.detailCategory.dataset.category =
      core?.normalizeCategory(detail.category) || "login";
    els.detailFavorite.setAttribute(
      "aria-pressed",
      detail.favorite === true ? "true" : "false",
    );
    els.detailFavorite.textContent = detail.favorite === true ? "★" : "☆";
    els.detailUnavailable.hidden = !detail.unavailable;
    els.detailUnavailable.textContent = detail.unavailable || "";
    els.detailNotes.textContent = detail.notes || "";
    els.detailUpdated.textContent = detail.updated_at
      ? "最近修改：" + detail.updated_at
      : "";
    els.detailFields.replaceChildren();
    const fields = detailFields(detail);
    for (const field of fields) {
      const row = document.createElement("div");
      row.className = "detail-field";
      row.dataset.fieldId = field.id || "";
      row.dataset.fieldType = field.type;
      const label = document.createElement("span");
      label.className = "field-label";
      label.textContent = field.label || "字段";
      const value = document.createElement("span");
      value.className = "field-value";
      const concealed = core
        ? core.concealedType(field.type, field.concealed)
        : ["password", "concealed", "cvv", "card_number"].includes(field.type);
      const key = field.id || field.label;
      const secret = activeRevealedSecret(key, detail.revision);
      const revealed = !!secret;
      value.textContent = concealed && !revealed
        ? field.has_value || field.value
          ? "••••••••••••"
          : field.value
        : revealed
          ? secret.value
          : field.value;
      if (concealed && revealed) value.classList.add("revealed");
      row.append(label, value);
      if (concealed || field.revealable === true) {
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.dataset.action = "toggle-reveal";
        toggle.textContent = revealed ? "隐藏" : "显示";
        toggle.addEventListener("click", () => {
          const key = field.id || field.label;
          if (activeRevealedSecret(key, detail.revision)) {
            hideRevealedSecret(key);
            renderDetail(lastDetail);
          } else {
            void revealSecret(field, detail);
          }
        });
        row.append(toggle);
      }
      const copy = document.createElement("button");
      copy.type = "button";
      copy.dataset.action = "copy-field";
      copy.textContent = "复制";
      copy.addEventListener("click", () =>
        concealed || field.revealable || field.has_value
          ? void copySecret(field, detail, copy)
          : void copyValue(field.value, copy),
      );
      row.append(copy);
      els.detailFields.append(row);
    }
    els.detailUrls.replaceChildren();
    for (const url of detail.urls || []) {
      const row = document.createElement("div");
      row.className = "detail-url";
      const label = document.createElement("span");
      label.textContent = url;
      const open = document.createElement("button");
      open.type = "button";
      open.dataset.action = "open-and-fill";
      open.textContent = "打开并填充";
      open.addEventListener("click", () => void openAndFill(detail, url));
      const copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "复制网址";
      copy.addEventListener("click", () => void copyValue(url, copy));
      row.append(label, open, copy);
      els.detailUrls.append(row);
    }
    els.detailTags.replaceChildren();
    for (const tag of detail.tags || []) {
      const item = document.createElement("span");
      item.className = "tag";
      item.textContent = tag;
      els.detailTags.append(item);
    }
    renderPasskeyDetail(detail);
    els.detailFill.disabled =
      !lastState?.connected ||
      !(lastState?.candidates || []).some(
        (row) =>
          row.id === detail.id && row.revision === detail.revision,
      );
    els.detailOtp.hidden = !detail.has_otp && !detail.otp_code;
    els.detailOpenFill.disabled = !(detail.urls || []).length;
    els.detailEdit.disabled = !!detail.readOnly;
    renderAttachments(detail);
  }
  globalThis.addEventListener?.("pagehide", () => {
    popupInactive = true;
    connectionEpoch++;
    actionGeneration++;
    // A pending act() may never resume on a hidden popup; release its main
    // busy flag so a restored popup is not stuck. Its late replies are already
    // generation-guarded, so they cannot touch the next operation.
    busy = false;
    vaultLoaded = false;
    if (els?.searchInput) els.searchInput.disabled = false;
    clearGeneratedData();
    clearRevealedSecrets();
  });
  globalThis.addEventListener?.("pageshow", () => {
    if (!popupInactive) return;
    popupInactive = false;
    // Force a fresh metadata read: the invalidated search query's finalizer
    // never re-enables the box, so restoring must own a new read. render() may
    // already start one (empty cache), and a user action may too, so only own
    // the read when no query was created while this state was in flight.
    const restoreEpoch = connectionEpoch;
    const restoreQueryGeneration = vaultQueryGeneration;
    vaultLoaded = false;
    // An unrelated action may drop this state reply (send resolves null), so
    // the follow-up read is decided from lastState and the query generation
    // only: an unrelated Refresh must not cancel the restore's own read.
    void send({ type: "state" }).then(() => {
      if (popupInactive || restoreEpoch !== connectionEpoch) return;
      if (lastState?.connected !== true) return;
      // renderVault() may already own a read (empty cache auto-refresh), and a
      // cached non-empty page must not suppress it; a user-started query owns
      // a newer generation and must not be duplicated.
      if (restoreQueryGeneration !== vaultQueryGeneration) return;
      vaultLoaded = true;
      void refreshVault(true);
    });
  });
  if (typeof document !== "undefined")
    document.addEventListener?.("visibilitychange", () => {
      if (document.visibilityState === "hidden") clearRevealedSecrets();
    });
  function clearRevealedSecrets() {
    secretGeneration++;
    const hadSecrets = revealedSecrets.size > 0;
    for (const timer of revealTimers.values()) clearTimeout(timer);
    revealTimers.clear();
    revealedSecrets.clear();
    pendingReveals.clear();
    // Clearing references alone leaves plaintext in the live DOM.
    if (hadSecrets && lastDetail && els) renderDetail(lastDetail);
  }
  function hideRevealedSecret(key) {
    pendingReveals.delete(key);
    const timer = revealTimers.get(key);
    if (timer) clearTimeout(timer);
    revealTimers.delete(key);
    revealedSecrets.delete(key);
  }
  function activeRevealedSecret(key, revision) {
    const secret = revealedSecrets.get(key);
    if (!secret) return null;
    if (secret.revision !== revision || secret.expiresAt <= Date.now()) {
      hideRevealedSecret(key);
      return null;
    }
    return secret;
  }
  function detailLeaseLive(detail, generation) {
    return generation === secretGeneration && !popupInactive &&
      document.visibilityState !== "hidden" && lastState?.connected === true &&
      document.body?.dataset?.view === "detail" && lastDetail === detail;
  }
  async function revealSecret(field, detail) {
    const generation = secretGeneration;
    if (!detailLeaseLive(detail, generation)) return;
    const key = field.id || field.label;
    const request = {};
    pendingReveals.set(key, request);
    try {
      const reply = await api.runtime.sendMessage({
        type: "reveal-field",
        id: detail.id,
        revision: detail.revision,
        field: key,
      });
      const result = reply?.revealedField;
      if (!detailLeaseLive(detail, generation) || pendingReveals.get(key) !== request) {
        if (result) result.value = "";
        return;
      }
      if (!result || result.field !== key || typeof result.value !== "string")
        throw Error("refused");
      const seconds = Number.isSafeInteger(result.expires_in_seconds)
        ? result.expires_in_seconds
        : 30;
      hideRevealedSecret(key);
      if (seconds <= 0 || seconds > 30) throw Error("refused");
      const value = result.value;
      result.value = "";
      revealedSecrets.set(key, {
        value,
        revision: detail.revision,
        expiresAt: Date.now() + seconds * 1000,
      });
      revealTimers.set(
        key,
        setTimeout(() => {
          hideRevealedSecret(key);
          if (lastDetail?.id === detail.id) renderDetail(lastDetail);
        }, seconds * 1000),
      );
      if (lastDetail?.id === detail.id) renderDetail(lastDetail);
    } catch {
      toast("无法显示该字段");
    }
  }
  async function copySecret(field, detail, button) {
    const generation = secretGeneration;
    if (!detailLeaseLive(detail, generation)) return;
    const key = field.id || field.label;
    try {
      const reply = await api.runtime.sendMessage({
        type: "copy-field",
        id: detail.id,
        revision: detail.revision,
        field: key,
      });
      const result = reply?.copiedField;
      if (!detailLeaseLive(detail, generation)) {
        if (result) result.value = "";
        return;
      }
      if (!result || typeof result.value !== "string")
        throw Error("refused");
      const value = result.value;
      result.value = "";
      await writeClipboard(value, button, result.clearAfterSeconds);
    } catch {
      toast("复制失败");
    }
  }
  async function writeClipboard(value, button, clearAfterSeconds) {
    if (typeof value !== "string") return;
    try {
      if (!globalThis.navigator?.clipboard?.writeText)
        throw Error("clipboard unavailable");
      await globalThis.navigator.clipboard.writeText(value);
    } catch {
      toast("复制失败");
      return;
    }
    const original = button.textContent;
    button.textContent = "已复制 ✓";
    if (feedbackTimer) clearTimeout(feedbackTimer);
    feedbackTimer = setTimeout(() => {
      feedbackTimer = null;
      if (button.isConnected !== false) button.textContent = original;
    }, 1500);
    const seconds = Number.isSafeInteger(clearAfterSeconds)
      ? clearAfterSeconds
      : Number.isSafeInteger(lastState?.clipboardClearSeconds)
        ? lastState.clipboardClearSeconds
        : 30;
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => {
      clipboardTimer = null;
      try {
        void globalThis.navigator?.clipboard?.writeText?.("");
      } catch {}
    }, seconds * 1000);
    toast(`已复制，${seconds} 秒后自动清除`);
  }
  async function copyValue(value, button) {
    return writeClipboard(value, button, lastState?.clipboardClearSeconds);
  }
  async function openAndFill(detail, url) {
    if (!detail || !url) return;
    try {
      const reply = await api.runtime.sendMessage({
        type: "open-and-fill",
        id: detail.id,
        revision: detail.revision,
        url,
        urls: detail.urls,
      });
      if (reply && typeof reply === "object" && reply.status) {
        lastState = { ...lastState, ...reply };
        text("#status", reply.status);
      }
      toast("已打开页面，加载完成后将填充");
    } catch {
      toast("打开并填充未完成");
    }
  }
  /* ---------------------------------------------------------------- *
   * Attachments. Vault state carries metadata only; file bytes exist  *
   * for at most one user-initiated upload or download inside this     *
   * page and are wiped on pagehide, lock or navigation.               *
   * ---------------------------------------------------------------- */
  function attachmentsSupported() {
    return lastState?.attachmentsSupported === true;
  }
  function attachmentStatus(value) {
    if (els?.attachmentStatus) els.attachmentStatus.textContent = value;
  }
  function clearAttachmentBuffers() {
    attachmentGeneration++;
    attachmentCancelled = true;
    attachmentBusy = false;
    const token = attachmentTransfer;
    attachmentTransfer = "";
    if (token)
      void Promise.resolve(
        api.runtime.sendMessage({ type: "attachment-cancel", transfer_id: token }),
      ).catch(() => {});
    for (const url of blobURLs) {
      try {
        globalThis.URL?.revokeObjectURL?.(url);
      } catch {}
    }
    blobURLs.clear();
    if (els?.attachmentList) els.attachmentList.replaceChildren();
    if (els?.attachmentStatus) els.attachmentStatus.textContent = "";
    if (els?.attachmentCancel) els.attachmentCancel.hidden = true;
  }
  function attachmentSizeLabel(size) {
    if (!Number.isSafeInteger(size) || size < 0) return "";
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KiB";
    return (size / (1024 * 1024)).toFixed(2) + " MiB";
  }
  function renderAttachments(detail) {
    if (!els?.attachmentList) return;
    const supported = attachmentsSupported();
    const locked = !supported || !!detail?.readOnly;
    if (els.attachmentUnsupported) els.attachmentUnsupported.hidden = supported;
    if (els.attachmentFile) els.attachmentFile.disabled = locked || attachmentBusy;
    if (els.attachmentUpload)
      els.attachmentUpload.disabled = locked || attachmentBusy;
    if (els.attachmentCancel) els.attachmentCancel.hidden = !attachmentBusy;
    els.attachmentList.replaceChildren();
    const list = Array.isArray(detail?.attachments) ? detail.attachments : [];
    for (const meta of list) {
      if (!meta || typeof meta !== "object") continue;
      const row = document.createElement("div");
      row.className = "attachment-row";
      row.dataset.attachmentId = meta.id;
      const name = document.createElement("span");
      name.className = "attachment-name";
      name.textContent = meta.file_name || "";
      name.title = meta.file_name || "";
      const size = document.createElement("span");
      size.className = "note";
      size.textContent = attachmentSizeLabel(meta.size);
      const download = document.createElement("button");
      download.type = "button";
      download.dataset.action = "download-attachment";
      download.textContent = "下载";
      download.disabled = attachmentBusy;
      download.addEventListener("click", () => void downloadAttachment(meta, detail));
      const remove = document.createElement("button");
      remove.type = "button";
      remove.dataset.action = "remove-attachment";
      remove.textContent = "删除";
      remove.disabled = locked || attachmentBusy;
      remove.addEventListener("click", () => void removeAttachment(meta, detail));
      row.append(name, size, download, remove);
      els.attachmentList.append(row);
    }
  }
  async function sha256Hex(bytes) {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle || typeof subtle.digest !== "function") throw Error("refused");
    const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
    let out = "";
    for (const byte of digest) out += byte.toString(16).padStart(2, "0");
    return out;
  }
  // Only the operation that owns the current generation may touch shared
  // attachment state or re-enable controls; stale finalizers stay silent.
  function finishAttachmentOperation(generation) {
    if (generation !== attachmentGeneration) return;
    attachmentBusy = false;
    attachmentCancelled = false;
    attachmentCommitting = false;
    if (
      lastDetail &&
      document.body?.dataset?.view === "detail" &&
      els?.attachmentList
    )
      renderAttachments(lastDetail);
  }
  function attachmentOperationAllowed(generation, id, revision) {
    return (
      generation === attachmentGeneration &&
      !attachmentCancelled &&
      !!lastDetail &&
      lastDetail.id === id &&
      lastDetail.revision === revision
    );
  }
  async function uploadAttachment(file) {
    if (!file || attachmentBusy || !lastDetail || !els) return;
    if (!attachmentsSupported()) {
      attachmentStatus("当前原生宿主不支持附件");
      return;
    }
    const detail = lastDetail;
    const id = detail.id;
    const revision = detail.revision;
    const generation = attachmentGeneration;
    attachmentCancelled = false;
    attachmentCommitting = false;
    const fileName = core ? core.safeFileName(file.name) : "";
    const size = file.size;
    if (
      !fileName ||
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > 2097152 ||
      typeof file.arrayBuffer !== "function"
    ) {
      attachmentStatus("仅支持 2 MiB 以内且名称安全的文件");
      return;
    }
    attachmentBusy = true;
    renderDetail(detail);
    attachmentStatus("正在读取文件…");
    let bytes = null;
    let committed = null;
    // The transfer token is operation-local: a late response may only cancel
    // its own token, never the token of a newer upload.
    let transferId = "";
    let commitStarted = false;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.length !== size) throw Error("refused");
      const sha256 = await sha256Hex(bytes);
      if (!attachmentOperationAllowed(generation, id, revision))
        throw Error("stale");
      const mime =
        typeof file.type === "string" && core?.validMimeType(file.type)
          ? file.type
          : "";
      const begin = await api.runtime.sendMessage({
        type: "attachment-begin",
        id,
        revision,
        file_name: fileName,
        size,
        sha256,
        ...(mime ? { mime_type: mime } : {}),
      });
      const transfer = begin?.attachmentTransfer;
      if (!transfer || typeof transfer.transfer_id !== "string")
        throw Error("refused");
      transferId = transfer.transfer_id;
      if (generation === attachmentGeneration) attachmentTransfer = transferId;
      if (!attachmentOperationAllowed(generation, id, revision))
        throw Error("stale");
      attachmentStatus("正在上传附件…");
      let offset = transfer.offset;
      while (offset < bytes.length) {
        if (!attachmentOperationAllowed(generation, id, revision))
          throw Error("stale");
        const chunk = bytes.subarray(
          offset,
          Math.min(offset + 65536, bytes.length),
        );
        const advanced = await api.runtime.sendMessage({
          type: "attachment-chunk",
          transfer_id: transferId,
          offset,
          data: core.base64Encode(chunk),
        });
        const next = advanced?.attachmentTransfer;
        if (
          !next ||
          next.transfer_id !== transferId ||
          next.offset !== offset + chunk.length
        )
          throw Error("refused");
        offset = next.offset;
      }
      if (!attachmentOperationAllowed(generation, id, revision))
        throw Error("stale");
      attachmentStatus("正在保存附件…");
      commitStarted = true;
      attachmentCommitting = true;
      const done = await api.runtime.sendMessage({
        type: "attachment-commit",
        transfer_id: transferId,
      });
      if (generation === attachmentGeneration && attachmentTransfer === transferId)
        attachmentTransfer = "";
      const saved = done?.attachmentSaved;
      if (
        !saved ||
        saved.item_id !== id ||
        !/^[a-f0-9]{64}$/.test(saved.revision || "")
      )
        throw Error("refused");
      committed = { id: saved.item_id, revision: saved.revision };
    } catch (error) {
      const token = transferId;
      if (token)
        void Promise.resolve(
          api.runtime.sendMessage({ type: "attachment-cancel", transfer_id: token }),
        ).catch(() => {});
      if (generation === attachmentGeneration && attachmentTransfer === token)
        attachmentTransfer = "";
      if (generation === attachmentGeneration && error?.message !== "stale")
        attachmentStatus(
          commitStarted
            ? "附件保存结果未确认，请刷新核实"
            : "附件上传未完成",
        );
    } finally {
      if (bytes) bytes.fill(0);
      finishAttachmentOperation(generation);
    }
    // A commit that lands after lock, navigation or pagehide is discarded.
    if (!committed || !attachmentOperationAllowed(generation, id, revision)) {
      if (generation === attachmentGeneration) attachmentCancelled = false;
      return;
    }
    await openDetail(committed);
    if (generation === attachmentGeneration) {
      attachmentStatus("附件已添加");
      toast("附件已添加");
    }
  }
  async function downloadAttachment(meta, detail) {
    if (!meta || attachmentBusy || !lastDetail || !els || !core) return;
    if (!core.validAttachmentMetadata(meta)) {
      toast("附件信息无效");
      return;
    }
    const id = detail.id;
    const revision = detail.revision;
    const generation = attachmentGeneration;
    attachmentCancelled = false;
    attachmentBusy = true;
    renderDetail(detail);
    attachmentStatus("正在下载附件…");
    const parts = [];
    let offset = 0;
    let total = 0;
    try {
      for (;;) {
        if (!attachmentOperationAllowed(generation, id, revision))
          throw Error("stale");
        const length =
          meta.size === 0 ? 1 : Math.min(65536, Math.max(1, meta.size - offset));
        const reply = await api.runtime.sendMessage({
          type: "attachment-read",
          id,
          revision,
          attachment_id: meta.id,
          offset,
          length,
        });
        const data = reply?.attachmentData;
        if (
          !data ||
          data.offset !== offset ||
          !data.attachment ||
          data.attachment.id !== meta.id
        )
          throw Error("refused");
        const chunk = core.base64Decode(data.data, 65536);
        if (!chunk) throw Error("refused");
        if (data.next_offset !== offset + chunk.length) {
          chunk.fill(0);
          throw Error("refused");
        }
        total += chunk.length;
        if (total > 2097152) {
          chunk.fill(0);
          throw Error("refused");
        }
        if (chunk.length) parts.push(chunk);
        offset = data.next_offset;
        if (data.done) {
          if (offset !== meta.size) throw Error("refused");
          break;
        }
        if (!chunk.length) throw Error("refused");
      }
      if (total !== meta.size) throw Error("refused");
      const merged = new Uint8Array(total);
      let at = 0;
      for (const part of parts) {
        merged.set(part, at);
        at += part.length;
      }
      for (const part of parts) part.fill(0);
      parts.length = 0;
      const digest = await sha256Hex(merged);
      if (digest !== meta.sha256) {
        merged.fill(0);
        throw Error("refused");
      }
      if (!attachmentOperationAllowed(generation, id, revision)) {
        merged.fill(0);
        throw Error("stale");
      }
      const blob = new Blob([merged], {
        type: meta.mime_type || "application/octet-stream",
      });
      merged.fill(0);
      const url = globalThis.URL.createObjectURL(blob);
      blobURLs.add(url);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = core.safeFileName(meta.file_name) || "attachment";
      anchor.rel = "noopener";
      anchor.click();
      setTimeout(() => {
        try {
          globalThis.URL.revokeObjectURL(url);
        } catch {}
        blobURLs.delete(url);
      }, 2000);
      attachmentStatus("附件已交给浏览器保存");
    } catch (error) {
      for (const part of parts) part.fill(0);
      parts.length = 0;
      if (generation === attachmentGeneration && error?.message !== "stale")
        attachmentStatus("附件下载未完成");
    } finally {
      finishAttachmentOperation(generation);
    }
  }
  async function removeAttachment(meta, detail) {
    if (!meta || attachmentBusy || !lastDetail || !els) return;
    const id = detail.id;
    const revision = detail.revision;
    const generation = attachmentGeneration;
    attachmentCancelled = false;
    attachmentBusy = true;
    renderDetail(detail);
    attachmentStatus("正在删除附件…");
    let removed = null;
    try {
      const reply = await api.runtime.sendMessage({
        type: "attachment-remove",
        id,
        revision,
        attachment_id: meta.id,
      });
      const result = reply?.attachmentRemoved;
      if (
        !result ||
        result.item_id !== id ||
        result.attachment_id !== meta.id ||
        !/^[a-f0-9]{64}$/.test(result.revision || "")
      )
        throw Error("refused");
      removed = { id: result.item_id, revision: result.revision };
    } catch (error) {
      if (generation === attachmentGeneration && error?.message !== "stale")
        attachmentStatus("附件删除未完成");
    } finally {
      finishAttachmentOperation(generation);
    }
    if (!removed || !attachmentOperationAllowed(generation, id, revision)) {
      if (generation === attachmentGeneration) attachmentCancelled = false;
      return;
    }
    await openDetail(removed);
    if (generation === attachmentGeneration) {
      attachmentStatus("附件已删除");
      toast("附件已删除");
    }
  }
  function editorValue(name) {
    return editorValues && Object.hasOwn(editorValues, name)
      ? editorValues[name]
      : undefined;
  }
  function addEditorInput(descriptor, value) {
    const label = document.createElement("label");
    label.className = "editor-field";
    label.dataset.field = descriptor.name;
    const caption = document.createElement("span");
    caption.textContent = descriptor.label;
    const input =
      descriptor.type === "textarea"
        ? document.createElement("textarea")
        : document.createElement("input");
    if (descriptor.type === "checkbox") {
      input.type = "checkbox";
      input.checked = value === true;
    } else {
      // HTMLTextAreaElement.type is a getter-only property. Assigning it in
      // strict mode throws and aborts openEditor before the view is shown.
      if (descriptor.type === "textarea") input.rows = 3;
      else
        input.type =
          descriptor.type === "password"
            ? "password"
            : descriptor.type === "email"
              ? "email"
              : descriptor.type === "tel"
                ? "tel"
                : "text";
      input.value =
        Array.isArray(value) ? value.join("\n") : value == null ? "" : value;
    }
    if (descriptor.required) input.required = true;
    if (descriptor.name === "password" || descriptor.name === "card_number")
      input.autocomplete = "new-password";
    input.dataset.field = descriptor.name;
    label.append(caption, input);
    els.editorFields.append(label);
    editorInputs.push({ descriptor, input });
  }
  function maskedNotesExist(detail) {
    if (!detail || detail.notes) return false;
    if (detail.has_notes === true) return true;
    const fields = Array.isArray(detail.fields) ? detail.fields : [];
    const entry = fields.find((field) => field && field.id === "notes");
    if (!entry) return false;
    return (
      entry.has_value === true ||
      entry.concealed === true ||
      entry.revealable === true
    );
  }
  function addClearNotesControl() {
    const label = document.createElement("label");
    label.className = "editor-field editor-clear-notes";
    label.dataset.field = "clear_notes";
    const caption = document.createElement("span");
    caption.textContent = "清空已保存备注";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = false;
    input.dataset.clearField = "notes";
    label.append(caption, input);
    els.editorFields.append(label);
    editorInputs.push({
      descriptor: { name: "clear_notes", type: "checkbox" },
      input,
    });
  }
  function addCustomField(field = {}) {
    const row = document.createElement("div");
    row.className = "custom-field";
    row.dataset.customField = "1";
    row.dataset.fieldId = typeof field.id === "string" ? field.id : "";
    row.dataset.sectionId = typeof field.section_id === "string" ? field.section_id : "";
    row.dataset.sectionTitle = typeof field.section_title === "string" ? field.section_title : "";
    row.dataset.purpose = typeof field.purpose === "string" ? field.purpose : "";
    const label = document.createElement("input");
    label.placeholder = "字段名称";
    label.value = field.label || "";
    label.dataset.customLabel = "1";
    const type = document.createElement("select");
    for (const value of ["text", "concealed", "url", "date", "multiline"]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent =
        value === "concealed"
          ? "隐藏文本"
          : value === "url"
            ? "网址"
            : value === "date"
              ? "日期"
              : value === "multiline"
                ? "多行文本"
                : "文本";
      type.append(option);
    }
    type.value = ["text", "concealed", "url", "date", "multiline"].includes(
      field.type,
    )
      ? field.type
      : "text";
    type.dataset.customType = "1";
    const value = document.createElement("input");
    value.placeholder = "值";
    value.value = field.value || "";
    value.dataset.customValue = "1";
    if (type.value === "concealed") value.type = "password";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "移除";
    remove.addEventListener("click", () => row.remove());
    row.append(label, type, value, remove);
    // An existing protected field can only be emptied via this explicit
    // checkbox; the form never renders the masked value itself.
    if (
      typeof field.id === "string" &&
      field.id &&
      typeof field.section_id === "string" &&
      field.section_id &&
      (field.concealed === true || type.value === "concealed")
    ) {
      const clearLabel = document.createElement("label");
      clearLabel.className = "custom-clear";
      const clear = document.createElement("input");
      clear.type = "checkbox";
      clear.checked = false;
      clear.dataset.customClear = "1";
      clear.dataset.clearField = core?.attachmentStableKey
        ? core.attachmentStableKey(field.section_id, field.id)
        : "";
      clearLabel.append(clear, document.createTextNode(" 清空"));
      row.append(clearLabel);
    }
    els.customFields.append(row);
    editorInputs.push({ descriptor: { name: "custom" }, input: value });
  }
  function openEditor(mode, categoryOrItem) {
    if (!els) return;
    // Entering the editor leaves the detail view: cancel any in-flight
    // attachment transfer so late chunks/commit cannot reopen the detail over
    // the editor, and re-render the masked detail so the hidden DOM no longer
    // retains revealed values. `lastDetail` metadata is kept for edit/cancel.
    clearAttachmentBuffers();
    clearRevealedSecrets();
    cancelPasskeyRemoval();
    // A pending detail read must not render over the editor the user just
    // opened. Release its vault ownership so its finalizer cannot clear the
    // busy state of the editor's own operation.
    passkeyDetailGeneration++;
    if (detailReadOperation) {
      const staleRead = detailReadOperation;
      detailReadOperation = 0;
      if (staleRead === vaultOperation) {
        vaultOperation++;
        vaultBusy = false;
      }
    }
    if (lastDetail) renderDetail(lastDetail);
    let category = "login",
      values = { title: "", urls: lastState?.origin ? [lastState.origin] : [] },
      item = null;
    if (mode === "edit" && categoryOrItem) {
      item = categoryOrItem;
      category = core?.normalizeCategory(item.category) || "login";
      values = { ...item };
      if (Array.isArray(item.sections))
        values.sections = item.sections.map((section) => ({
          ...section,
          fields: (section.fields || []).map((field) => ({ ...field })),
        }));
      if (Array.isArray(item.fields))
        values.fields = item.fields
          .filter(
            (field) =>
              ![
                "username",
                "password",
                "notes",
                "otp",
                "cc-number",
                "cc-csc",
                "cc-pin",
              ].includes(field.id) &&
              !String(field.id || "").startsWith("identity:"),
          )
          .map((field) => ({ ...field }));
    } else {
      category = core?.normalizeCategory(categoryOrItem) || "login";
    }
    if (!EDITOR_TEMPLATES[category]) category = "login";
    wipeEditor();
    editorMode = mode;
    editorCategory = category;
    editorValues = values;
    els.editorHeading.textContent =
      (mode === "edit" ? "编辑" : "新建") + categoryLabel(category);
    for (const descriptor of EDITOR_TEMPLATES[category])
      addEditorInput(descriptor, editorValue(descriptor.name));
    editorHadSections =
      mode === "edit" &&
      Array.isArray(values.sections) &&
      values.sections.length > 0;
    if (mode === "edit") {
      // publicDetail also flattens section fields into `fields` using their
      // qualified stable key; render each section field exactly once from
      // `sections` and keep genuinely standalone custom fields.
      const sectionKeys = new Set();
      for (const section of Array.isArray(values.sections) ? values.sections : [])
        for (const field of Array.isArray(section?.fields) ? section.fields : [])
          if (typeof field?.id === "string" && field.id)
            sectionKeys.add("section:" + section.id + ":" + field.id);
      for (const field of Array.isArray(values.fields) ? values.fields : []) {
        const key =
          typeof field?.id === "string" && field.id.startsWith("section:")
            ? field.id
            : field?.section_id && field?.id
              ? "section:" + field.section_id + ":" + field.id
              : "";
        if (key && sectionKeys.has(key)) continue;
        addCustomField(field);
      }
      for (const section of Array.isArray(values.sections) ? values.sections : [])
        for (const field of Array.isArray(section?.fields) ? section.fields : [])
          addCustomField({
            ...field,
            section_id: section.id,
            section_title: section.title,
          });
      if (maskedNotesExist(mode === "edit" ? categoryOrItem || values : values))
        addClearNotesControl();
    }
    els.editorGenerate.hidden = !EDITOR_TEMPLATES[category].some(
      (descriptor) => descriptor.generate,
    );
    els.editorView.hidden = false;
    els.detailView.hidden = true;
    els.vaultView.hidden = true;
    document.body.dataset.view = "editor";
  }
  function collectEditorItem() {
    const item = {
      category: editorCategory,
      title: "",
      favorite: false,
      urls: [],
      tags: [],
      fields: [],
    };
    for (const { descriptor, input } of editorInputs) {
      if (descriptor.name === "custom") continue;
      const value =
        descriptor.type === "checkbox" ? input.checked : input.value;
      if (descriptor.name === "urls")
        item.urls = String(value)
          .split("\n")
          .map((entry) => entry.trim())
          .filter(Boolean);
      else if (descriptor.name === "tags")
        item.tags = String(value)
          .split(",")
          .map((entry) => entry.trim())
          .filter(Boolean);
      else if (descriptor.name === "favorite") item.favorite = value === true;
      else item[descriptor.name] = value;
    }
    editorConflict = "";
    item.clear_fields = [];
    const sections = [];
    const sectionIndex = new Map();
    if (els?.customFields)
      for (const row of [...els.customFields.children]) {
        const label = row.querySelector?.('[data-custom-label="1"]');
        const type = row.querySelector?.('[data-custom-type="1"]');
        const value = row.querySelector?.('[data-custom-value="1"]');
        if (!label || !value) continue;
        const fieldLabel = String(label.value || "").trim();
        if (!fieldLabel) continue;
        let id = row.dataset.fieldId || "";
        let sectionID = row.dataset.sectionId || "";
        if (id.startsWith("section:")) {
          const parts = id.split(":");
          if (parts.length === 3) {
            sectionID = sectionID || parts[1];
            id = parts[2];
          }
        }
        const rawValue = String(value.value || "");
        const clearBox = row.querySelector?.('[data-custom-clear="1"]');
        const explicitClear = clearBox?.checked === true;
        const clearKey =
          sectionID && id && core?.attachmentStableKey
            ? core.attachmentStableKey(sectionID, id)
            : "";
        if (explicitClear) {
          if (!clearKey) {
            editorConflict = "只能清空已保存的隐藏自定义字段";
            return null;
          }
          if (rawValue !== "") {
            editorConflict = "清空自定义字段时请勿填写新值";
            return null;
          }
          if (!item.clear_fields.includes(clearKey))
            item.clear_fields.push(clearKey);
        }
        const entry = {
          ...(id ? { id } : {}),
          ...(sectionID ? { section_id: sectionID } : {}),
          ...(row.dataset.sectionTitle
            ? { section_title: row.dataset.sectionTitle }
            : {}),
          ...(row.dataset.purpose ? { purpose: row.dataset.purpose } : {}),
          label: fieldLabel,
          type: type?.value || "text",
          value: explicitClear ? "" : rawValue,
          concealed: type?.value === "concealed",
        };
        if (sectionID) {
          let section = sectionIndex.get(sectionID);
          if (!section) {
            section = {
              id: sectionID,
              title: row.dataset.sectionTitle || "自定义字段",
              fields: [],
            };
            sectionIndex.set(sectionID, section);
            sections.push(section);
          }
          section.fields.push(entry);
        } else item.fields.push(entry);
      }
    if (editorHadSections || sections.length) item.sections = sections;
    const clearNotes = editorInputs.some(
      (entry) =>
        entry.descriptor?.name === "clear_notes" && entry.input.checked === true,
    );
    if (clearNotes) {
      const existing = String(item.notes ?? item.content ?? "");
      if (existing !== "") {
        editorConflict = "清空备注时请勿填写新的备注内容";
        return null;
      }
      if (!item.clear_fields.includes("notes")) item.clear_fields.push("notes");
      if (Object.hasOwn(item, "notes")) item.notes = "";
      else if (Object.hasOwn(item, "content")) item.content = "";
    }
    return item;
  }
  async function saveEditor() {
    if (vaultBusy) return;
    const generation = editorGeneration;
    const item = collectEditorItem();
    if (!item) {
      toast(editorConflict || "无法保存编辑内容");
      return;
    }
    if (!item.title || !item.title.trim()) {
      toast("请填写标题");
      return;
    }
    const operation = beginVaultOperation();
    els.editorSave.disabled = true;
    let saved = null,
      wasEdit = false;
    const clearedKeys = Array.isArray(item.clear_fields)
      ? [...item.clear_fields]
      : [];
    try {
      const reply = await api.runtime.sendMessage({
        type: "item-save",
        mode: editorMode,
        id: lastDetail?.id,
        revision: lastDetail?.revision,
        item,
      });
      if (generation !== editorGeneration || !lastState?.connected || popupInactive) return;
      if (!reply || !reply.saved) throw Error("refused");
      lastState = { ...lastState, ...reply };
      saved = reply.saved;
      wasEdit = editorMode === "edit";
      wipeEditor();
      vaultLoaded = false;
    } catch {
      toast("保存未完成；请确认原生金库支持条目编辑");
    } finally {
      if (finishVaultOperation(operation) && els?.editorSave) els.editorSave.disabled = false;
    }
    // The save transaction owns vaultBusy. Complete it before handing the
    // committed revision to the guarded detail/refresh helpers; otherwise they
    // return early and leave an empty editor or a stale vault list.
    if (!saved) return;
    toast("已保存");
    if (wasEdit) {
      await openDetail({ id: saved.item_id, revision: saved.revision });
      if (typeof clearUnsupportedNotice === "function")
        clearUnsupportedNotice(lastDetail, clearedKeys);
    }
    else {
      wipeDetail();
      showView("vault");
      await refreshVault(true);
    }
  }
  async function generateEditorPassword() {
    if (vaultBusy) return;
    const generation = editorGeneration;
    const operation = beginVaultOperation();
    try {
      const reply = await api.runtime.sendMessage({
        type: "generate",
        options: lastState?.generatorDefaults || {},
      });
      if (!reply?.generatedPassword) throw Error("refused");
      const password = reply.generatedPassword;
      reply.generatedPassword = "";
      if (generation !== editorGeneration || !lastState?.connected || popupInactive || document.body.dataset.view !== "editor") return;
      const target = editorInputs.find(
        (entry) =>
          entry.descriptor.name === "password" ||
          entry.descriptor.name === "card_number",
      );
      if (target) target.input.value = password;
    } catch {
      toast("无法生成密码");
    } finally {
      finishVaultOperation(operation);
    }
  }
  function clearTargetStillPresent(detail, key) {
    if (!detail) return false;
    const entry = (Array.isArray(detail.fields) ? detail.fields : []).find(
      (field) => field && field.id === key,
    );
    if (!entry) return false;
    if (entry.has_value === true) return true;
    if (entry.concealed === true || entry.revealable === true) return true;
    return typeof entry.value === "string" && entry.value !== "";
  }
  function clearUnsupportedNotice(detail, keys) {
    if (!keys.length) return;
    const still = keys.filter((key) => clearTargetStillPresent(detail, key));
    if (!still.length) return;
    if (els?.detailUnavailable) {
      els.detailUnavailable.hidden = false;
      els.detailUnavailable.textContent =
        "当前原生宿主未确认清空字段，请升级原生宿主后重试";
    }
    toast("宿主未确认清空，请升级原生宿主");
  }
  function classifyDetailAction(message) {
    const detail = lastDetail;
    const generation = passkeyDetailGeneration;
    return api.runtime.sendMessage(message).then((reply) => {
      if (generation !== passkeyDetailGeneration || detail !== lastDetail ||
          !lastState?.connected || popupInactive) return null;
      if (reply && typeof reply === "object") {
        if (reply.status) lastState = { ...lastState, ...reply };
        if (reply.saved) {
          lastDetail = lastDetail
            ? { ...lastDetail, revision: reply.saved.revision }
            : lastDetail;
        }
      }
      return reply;
    });
  }
  async function detailFavorite() {
    if (!lastDetail) return;
    try {
      const reply = await classifyDetailAction({
        type: "item-state",
        id: lastDetail.id,
        revision: lastDetail.revision,
        favorite: lastDetail.favorite !== true,
      });
      if (!reply?.itemState) throw Error("refused");
      lastDetail = {
        ...lastDetail,
        favorite: lastDetail.favorite !== true,
        revision: reply.itemState.revision,
      };
      renderDetail(lastDetail);
    } catch {
      toast("收藏状态未更新");
    }
  }
  async function detailTrash() {
    if (!lastDetail) return;
    try {
      const reply = await classifyDetailAction({
        type: "item-state",
        id: lastDetail.id,
        revision: lastDetail.revision,
        state: "trashed",
      });
      if (!reply?.itemState) throw Error("refused");
      vaultLoaded = false;
      wipeSensitiveViews();
      showView("vault");
      await refreshVault(true);
      toast("条目已移至废纸篓");
    } catch {
      toast("无法移至废纸篓");
    }
  }
  function openOptions() {
    try {
      const result = api.runtime.openOptionsPage?.();
      if (result && typeof result.catch === "function") result.catch(() => {});
      else if (!api.runtime.openOptionsPage) {
        const url = api.runtime.getURL
          ? api.runtime.getURL("options.html")
          : "options.html";
        void api.tabs?.create?.({ url });
      }
    } catch {}
  }
  function initVault() {
    els = {
      lockedView: q("#locked-view"),
      vaultView: q("#vault-view"),
      detailView: q("#detail-view"),
      editorView: q("#editor-view"),
      searchInput: q("#search-input"),
      searchClear: q("#search-clear"),
      newItemBtn: q("#new-item-btn"),
      newItemMenu: q("#new-item-menu"),
      filterTabs: q("#filter-tabs"),
      vaultList: q("#vault-list"),
      vaultCount: q("#vault-count"),
      vaultEmpty: q("#vault-empty"),
      siteDisableInline: q("#site-disable-inline"),
      siteNeverSave: q("#site-never-save"),
      lockButton: q("#lock-btn"),
      optionsButton: q("#options-btn"),
      openOptions: q("#open-options"),
      unlockConnect: q("#unlock-connect"),
      toast: q("#toast"),
      detailBack: q("#detail-back"),
      detailCategory: q("#detail-category"),
      detailFavorite: q("#detail-favorite"),
      detailEdit: q("#detail-edit"),
      detailTitle: q("#detail-title"),
      detailUnavailable: q("#detail-unavailable"),
      detailFill: q("#detail-fill"),
      detailOtp: q("#detail-otp"),
      detailOpenFill: q("#detail-open-fill"),
      detailTrash: q("#detail-trash"),
      detailFields: q("#detail-fields"),
      detailUrls: q("#detail-urls"),
      detailNotes: q("#detail-notes"),
      detailTags: q("#detail-tags"),
      detailUpdated: q("#detail-updated"),
      vaultPasskeyUnsupported: q("#vault-passkey-unsupported"),
      passkeyUnsupported: q("#vault-passkey-unsupported"),
      passkeyDetail: q("#passkey-detail"),
      passkeyDetailUnsupported: q("#passkey-detail-unsupported"),
      passkeyRp: q("#passkey-rp"),
      passkeyUsername: q("#passkey-username"),
      passkeyDisplayName: q("#passkey-display-name"),
      passkeyRemove: q("#passkey-remove"),
      passkeyRemoveConfirm: q("#passkey-remove-confirm"),
      passkeyRemoveCancel: q("#passkey-remove-cancel"),
      passkeyRemoveWarning: q("#passkey-remove-warning"),
      passkeyStatus: q("#passkey-status"),
      editorBack: q("#editor-back"),
      editorHeading: q("#editor-heading"),
      editorFields: q("#editor-fields"),
      customFields: q("#editor-custom-fields"),
      editorAddCustom: q("#editor-add-custom"),
      editorGenerate: q("#editor-generate"),
      editorSave: q("#editor-save"),
      editorCancel: q("#editor-cancel"),
      attachmentList: q("#attachment-list"),
      attachmentStatus: q("#attachment-status"),
      attachmentFile: q("#attachment-file"),
      attachmentUpload: q("#attachment-upload"),
      attachmentCancel: q("#attachment-cancel"),
      attachmentUnsupported: q("#attachment-unsupported"),
    };
    els.searchInput.addEventListener("input", (event) => {
      searchQuery = String(event.target.value || "");
      if (activeFilter === "passkeys") vaultItems = [];
      renderVaultList();
      scheduleVaultSearch();
    });
    els.searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        searchQuery = "";
        els.searchInput.value = "";
        if (activeFilter === "passkeys") vaultItems = [];
        renderVaultList();
        scheduleVaultSearch();
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        els.vaultList.children[0]?.focus?.();
      } else if (event.key === "Enter") {
        const first = els.vaultList.children[0];
        if (first) {
          event.preventDefault();
          first.click?.();
        }
      }
    });
    els.searchClear.addEventListener("click", () => {
      searchQuery = "";
      els.searchInput.value = "";
      if (activeFilter === "passkeys") vaultItems = [];
      renderVaultList();
      void refreshVault(true);
    });
    els.newItemBtn.addEventListener("click", () => {
      els.newItemMenu.hidden = !els.newItemMenu.hidden;
      els.newItemBtn.setAttribute(
        "aria-expanded",
        els.newItemMenu.hidden ? "false" : "true",
      );
    });
    for (const button of all("#new-item-menu [data-category]"))
      button.addEventListener("click", () => {
        els.newItemMenu.hidden = true;
        els.newItemBtn.setAttribute("aria-expanded", "false");
        openEditor("create", button.dataset.category);
      });
    for (const tab of all("#filter-tabs [data-filter]"))
      tab.addEventListener("click", () => {
        activeFilter = Object.hasOwn(FILTER_LABELS, tab.dataset.filter)
          ? tab.dataset.filter
          : "all";
        if (searchTimer) clearTimeout(searchTimer);
        searchTimer = null;
        // A new server query owns the list; never client-filter the previous
        // truncated page while the host is still filtering.
        vaultItems = [];
        if (lastState) lastState = { ...lastState, vaultItems: [] };
        renderVaultList();
        void refreshVault(true);
      });
    for (const tab of all("#filter-tabs [data-filter]"))
      tab.addEventListener("keydown", event => {
        const tabs = all("#filter-tabs [data-filter]");
        const at = tabs.indexOf(tab);
        let next;
        if (event.key === "ArrowRight") next = (at + 1) % tabs.length;
        else if (event.key === "ArrowLeft") next = (at + tabs.length - 1) % tabs.length;
        else if (event.key === "Home") next = 0;
        else if (event.key === "End") next = tabs.length - 1;
        else return;
        event.preventDefault();
        tabs[next].focus?.();
        tabs[next].click?.();
      });
    els.siteDisableInline.addEventListener("change", (event) => {
      void api.runtime
        .sendMessage({
          type: "site-settings",
          disabledInline: event.target.checked,
        })
        .then((reply) => {
          if (reply && typeof reply === "object") {
            lastState = { ...lastState, ...reply };
            render(lastState);
          }
        })
        .catch(() => toast("网站设置未保存"));
    });
    els.siteNeverSave.addEventListener("change", (event) => {
      void api.runtime
        .sendMessage({
          type: "site-settings",
          neverSave: event.target.checked,
        })
        .then((reply) => {
          if (reply && typeof reply === "object") {
            lastState = { ...lastState, ...reply };
            render(lastState);
          }
        })
        .catch(() => toast("网站设置未保存"));
    });
    els.lockButton.addEventListener("click", () => {
      connectionEpoch++;
      actionGeneration++;
      const lockEpoch = connectionEpoch;
      const lockAction = actionGeneration;
      // Lock intent preempts any pending act(): clear generated data now and
      // release the preempted action's busy flag so it cannot stick.
      clearGeneratedData();
      busy = false;
      if (lastState) render(lastState);
      wipeSensitiveViews();
      cancelPasskeyRemoval();
      clearAttachmentBuffers();
      const operation = beginVaultOperation();
      // A deferred lock acknowledgement only owns this popup while its epoch,
      // action and vault operation are still current; a reconnect or newer
      // lock must not be overwritten by an older reply.
      const lockOwned = () =>
        !popupInactive &&
        lockEpoch === connectionEpoch &&
        lockAction === actionGeneration &&
        operation === vaultOperation;
      void api.runtime
        .sendMessage({ type: "lock" })
        .then((reply) => {
          if (!lockOwned()) return;
          if (reply && typeof reply === "object") {
            lastState = reply;
            render(reply);
          }
          toast("已锁定");
        })
        .catch(() => {
          if (lockOwned()) toast("锁定失败");
        })
        .finally(() => {
          const owned = finishVaultOperation(operation);
          if (owned && els && lockOwned())
            els.lockButton.disabled = !lastState?.connected;
        });
    });
    els.optionsButton.addEventListener("click", openOptions);
    els.openOptions.addEventListener("click", openOptions);
    els.unlockConnect.addEventListener("click", () => {
      const connect = document.querySelector("#connect");
      if (typeof connect.click === "function") connect.click();
      else connect.listeners?.get("click")?.();
    });
    els.detailBack.addEventListener("click", () => {
      wipeDetail();
      showView("vault");
      renderVaultList();
    });
    els.detailFavorite.addEventListener("click", () => void detailFavorite());
    els.detailEdit.addEventListener("click", () => {
      if (lastDetail) openEditor("edit", lastDetail);
    });
    els.detailFill.addEventListener("click", () => {
      if (!lastDetail) return;
      void classifyDetailAction({
        type: "fill",
        id: lastDetail.id,
        revision: lastDetail.revision,
      }).catch(() => toast("请先读取当前网站候选"));
    });
    els.detailOtp.addEventListener("click", () => {
      if (!lastDetail) return;
      void classifyDetailAction({
        type: "otp",
        id: lastDetail.id,
        revision: lastDetail.revision,
      }).catch(() => toast("验证码填充未完成"));
    });
    els.detailOpenFill.addEventListener("click", () => {
      if (lastDetail?.urls?.length)
        void openAndFill(lastDetail, lastDetail.urls[0]);
    });
    els.detailTrash.addEventListener("click", () => void detailTrash());
    els.passkeyRemove.addEventListener("click", () =>
      requestPasskeyRemovalConfirmation(),
    );
    els.passkeyRemoveConfirm.addEventListener("click", () =>
      void confirmPasskeyRemoval(),
    );
    els.passkeyRemoveCancel.addEventListener("click", () => {
      cancelPasskeyRemoval();
      passkeyStatusText = "已取消删除";
      renderPasskeyDetail(lastDetail);
    });
    els.editorBack.addEventListener("click", () => {
      const editing = editorMode === "edit" && lastDetail;
      wipeEditor();
      if (editing) {
        renderDetail(lastDetail);
        showView("detail");
      } else showView("vault");
    });
    els.editorCancel.addEventListener("click", () => {
      wipeEditor();
      wipeDetail();
      showView("vault");
    });
    els.editorAddCustom.addEventListener("click", () => addCustomField());
    els.editorGenerate.addEventListener("click", () =>
      void generateEditorPassword(),
    );
    els.editorSave.addEventListener("click", () => void saveEditor());
    els.attachmentUpload.addEventListener("click", () => {
      if (els.attachmentFile.disabled) return;
      if (typeof els.attachmentFile.click === "function")
        els.attachmentFile.click();
    });
    els.attachmentFile.addEventListener("change", (event) => {
      const files = event?.target?.files;
      const file = files && files.length ? files[0] : null;
      if (!file) return;
      if (event.target) event.target.value = "";
      void uploadAttachment(file);
    });
    els.attachmentCancel.addEventListener("click", () => {
      const committing = attachmentCommitting;
      clearAttachmentBuffers();
      attachmentStatus(
        committing
          ? "已停止等待 · 附件保存结果未确认，请刷新核实"
          : "已取消上传",
      );
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        if (document.body.dataset.view === "editor") {
          wipeEditor();
          wipeDetail();
          showView("vault");
        } else if (document.body.dataset.view === "detail") {
          wipeDetail();
          showView("vault");
          renderVaultList();
        }
      }
    });
    globalThis.addEventListener?.("pagehide", wipeSensitiveViews);
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
  document.querySelector("#offer-save-logins").addEventListener(
    "change",
    (event) =>
      void act({ type: "settings", offerSaveLogins: event.target.checked }),
  );
  document
    .querySelector("#clear-never-save")
    .addEventListener("click", () => void act({ type: "clear-never-save-origin" }));
  document.querySelector("#commit-staged-save").addEventListener("click", () => {
    const pending = lastState?.pendingSave;
    if (!pending) return;
    void act({
      type: "commit-staged-save",
      stageId: pending.stageId,
      mode: pending.mode,
      itemId: pending.existingItemId,
      revision: pending.existingRevision,
      title: query("#pending-save-title").value,
    });
  });
  document
    .querySelector("#dismiss-staged-save")
    .addEventListener("click", () => {
      const pending = lastState?.pendingSave;
      if (!pending) return;
      void act({ type: "dismiss-staged-save", stageId: pending.stageId });
    });
  document.querySelector("#never-save-origin").addEventListener("click", () => {
    const pending = lastState?.pendingSave;
    if (!pending) return;
    void act({ type: "never-save-origin", stageId: pending.stageId });
  });
  document.querySelector("#gen-mode").addEventListener("change", () => {
    applyGeneratorMode();
    regenerate();
  });
  document.querySelector("#gen-length").addEventListener("input", () => {
    const mode = generatorMode();
    generatorValues[mode] = Number(query("#gen-length").value);
    query("#gen-length-value").textContent = query("#gen-length").value;
  });
  document
    .querySelector("#gen-length")
    .addEventListener("change", () => regenerate());
  for (const selector of [
    "#gen-digits",
    "#gen-symbols",
    "#gen-capitalize",
    "#gen-separator",
  ])
    document
      .querySelector(selector)
      .addEventListener("change", () => regenerate());
  document
    .querySelector("#gen-regenerate")
    .addEventListener("click", () => regenerate());
  document.querySelector("#gen-fill").addEventListener("click", () => {
    if (!generatedPassword) {
      setGeneratorStatus("请先生成密码");
      return;
    }
    setGeneratorStatus("正在填充…");
    void act({
      type: "generator-fill",
      ...generatorParams(),
      password: generatedPassword,
      profile: generatedProfile || undefined,
    });
  });
  document
    .querySelector("#gen-copy")
    .addEventListener("click", () => void copyGenerated());
  if (vaultEnabled) initVault();
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
