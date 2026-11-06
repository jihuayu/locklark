(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  const core = globalThis.LocklarkCore || null;
  const vaultEnabled = document.body?.dataset?.vault === "1";
  let busy = false,
    renderedCandidates = "",
    renderedHistory = "",
    lastState = null,
    actionGeneration = 0,
    requestSequence = 0,
    renderedSequence = 0,
    generatorInitialized = false,
    generatedPassword = "",
    generatedProfile = null,
    generatorValues = { random: 24, memorable: 4, pin: 6 };
  const query = (selector) => document.querySelector(selector);
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
  function render(state) {
    lastState = state;
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
    const list = query("#candidates");
    const signature = JSON.stringify({
      rows: state.candidates,
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
      list.append(container);
    }
    if (vaultEnabled) renderVault(state);
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
        return null;
      renderedSequence = sequence;
      render(state);
      return state;
    } catch {
      if (generation !== actionGeneration || sequence <= renderedSequence)
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
    vaultItems = [],
    lastDetail = null,
    revealedFields = new Set(),
    editorMode = "",
    editorCategory = "",
    editorValues = null,
    editorInputs = [],
    searchTimer = null,
    toastTimer = null,
    clipboardTimer = null,
    feedbackTimer = null,
    els = null;

  function q(selector) {
    return document.querySelector(selector);
  }
  function all(selector) {
    return document.querySelectorAll
      ? [...document.querySelectorAll(selector)]
      : [];
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
    if (!els) return;
    els.vaultView.hidden = name !== "vault";
    els.detailView.hidden = name !== "detail";
    els.editorView.hidden = name !== "editor";
    document.body.dataset.view = name;
  }
  function wipeDetail() {
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
    revealedFields.clear();
  }
  function wipeEditor() {
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
  }
  function wipeSensitiveViews() {
    wipeDetail();
    wipeEditor();
    if (els) showView("vault");
  }
  function categoryLabel(category) {
    return CATEGORY_LABELS[category] || "条目";
  }
  function stateItems() {
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
    els.lockButton.disabled = !state.connected || vaultBusy;
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
    const items = filteredItems();
    const list = els.vaultList;
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
      const subtitle = document.createElement("span");
      subtitle.className = "vault-item-subtitle";
      subtitle.textContent = item.subtitle || item.username || "";
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = categoryLabel(item.category);
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
    els.vaultCount.textContent = `${items.length} 个条目 · ${
      FILTER_LABELS[activeFilter] || "全部"
    }`;
    els.vaultEmpty.hidden = items.length !== 0;
    els.vaultEmpty.textContent =
      activeFilter === "favorites"
        ? "暂无收藏条目"
        : activeFilter === "suggested"
          ? "当前网站无匹配条目"
          : searchQuery
            ? "没有匹配的条目"
            : "金库中暂无条目";
    for (const tab of all("#filter-tabs [data-filter]")) {
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
      wipeSensitiveViews();
    } else if (Array.isArray(state.vaultItems) && state.vaultItems.length) {
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
  async function refreshVault(silent = false) {
    if (!vaultEnabled || vaultBusy || !lastState?.connected) return;
    vaultBusy = true;
    if (els?.searchInput) els.searchInput.disabled = true;
    try {
      const reply = await api.runtime.sendMessage({
        type: "vault-search",
        query: searchQuery,
        category: activeFilter,
      });
      if (reply && typeof reply === "object") {
        if (reply.status || typeof reply.connected === "boolean")
          lastState = { ...lastState, ...reply };
        if (Array.isArray(reply.vaultItems)) vaultItems = reply.vaultItems;
        vaultLoaded = true;
        renderVaultList();
      }
    } catch {
      if (!silent) toast("无法读取金库条目");
    } finally {
      vaultBusy = false;
      if (els?.searchInput) els.searchInput.disabled = false;
      renderLockedView(lastState || {});
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
    if (!item || vaultBusy) return;
    vaultBusy = true;
    try {
      const reply = await api.runtime.sendMessage({
        type: "item-get",
        id: item.id,
        revision: item.revision,
      });
      if (!reply?.detail) throw Error("refused");
      if (typeof reply.connected === "boolean")
        lastState = { ...lastState, ...reply };
      lastDetail = reply.detail;
      revealedFields.clear();
      renderDetail(reply.detail);
      showView("detail");
    } catch {
      toast("无法读取条目详情");
    } finally {
      vaultBusy = false;
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
    if (!fields.some((field) => field.id === "password") && detail.password)
      fields.push({
        id: "password",
        label: "密码",
        type: "password",
        value: detail.password,
        concealed: true,
      });
    if (
      !fields.some((field) => field.type === "totp") &&
      (detail.otp_code || detail.otp_secret)
    )
      fields.push({
        id: "otp",
        label: "一次性验证码",
        type: "totp",
        value: detail.otp_code || "",
        concealed: false,
      });
    return fields;
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
      const revealed = revealedFields.has(field.id || field.label);
      value.textContent = concealed && !revealed ? "••••••••••••" : field.value;
      if (concealed && revealed) value.classList.add("revealed");
      row.append(label, value);
      if (concealed) {
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.dataset.action = "toggle-reveal";
        toggle.textContent = revealed ? "隐藏" : "显示";
        toggle.addEventListener("click", () => {
          const key = field.id || field.label;
          if (revealedFields.has(key)) revealedFields.delete(key);
          else revealedFields.add(key);
          renderDetail(lastDetail);
        });
        row.append(toggle);
      }
      const copy = document.createElement("button");
      copy.type = "button";
      copy.dataset.action = "copy-field";
      copy.textContent = "复制";
      copy.addEventListener(
        "click",
        () => void copyValue(field.value, copy),
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
    els.detailFill.disabled =
      !lastState?.connected ||
      !(lastState?.candidates || []).some(
        (row) =>
          row.id === detail.id && row.revision === detail.revision,
      );
    els.detailOtp.hidden = !detail.has_otp && !detail.otp_code;
    els.detailOpenFill.disabled = !(detail.urls || []).length;
    els.detailEdit.disabled = !!detail.readOnly;
  }
  async function copyValue(value, button) {
    if (typeof value !== "string" || value.length === 0) return;
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
    const seconds = Number.isSafeInteger(lastState?.clipboardClearSeconds)
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
      input.type =
        descriptor.type === "password"
          ? "password"
          : descriptor.type === "email"
            ? "email"
            : descriptor.type === "tel"
              ? "tel"
              : "text";
      if (descriptor.type === "textarea") input.rows = 3;
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
  function addCustomField(field = {}) {
    const row = document.createElement("div");
    row.className = "custom-field";
    row.dataset.customField = "1";
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
    els.customFields.append(row);
    editorInputs.push({ descriptor: { name: "custom" }, input: value });
  }
  function openEditor(mode, categoryOrItem) {
    if (!els) return;
    let category = "login",
      values = { title: "", urls: lastState?.origin ? [lastState.origin] : [] },
      item = null;
    if (mode === "edit" && categoryOrItem) {
      item = categoryOrItem;
      category = core?.normalizeCategory(item.category) || "login";
      values = { ...item };
      if (Array.isArray(item.fields))
        values.fields = item.fields.map((field) => ({ ...field }));
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
    if (mode === "edit" && Array.isArray(values.fields))
      for (const field of values.fields) addCustomField(field);
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
    if (els?.customFields)
      for (const row of [...els.customFields.children]) {
        const label = row.querySelector?.('[data-custom-label="1"]');
        const type = row.querySelector?.('[data-custom-type="1"]');
        const value = row.querySelector?.('[data-custom-value="1"]');
        if (!label || !value) continue;
        const fieldLabel = String(label.value || "").trim();
        if (!fieldLabel) continue;
        item.fields.push({
          label: fieldLabel,
          type: type?.value || "text",
          value: String(value.value || ""),
        });
      }
    return item;
  }
  async function saveEditor() {
    if (vaultBusy) return;
    const item = collectEditorItem();
    if (!item.title || !item.title.trim()) {
      toast("请填写标题");
      return;
    }
    vaultBusy = true;
    els.editorSave.disabled = true;
    try {
      const reply = await api.runtime.sendMessage({
        type: "item-save",
        mode: editorMode,
        id: lastDetail?.id,
        revision: lastDetail?.revision,
        item,
      });
      if (!reply || !reply.saved) throw Error("refused");
      lastState = { ...lastState, ...reply };
      const saved = reply.saved;
      const wasEdit = editorMode === "edit";
      wipeEditor();
      vaultLoaded = false;
      if (wasEdit) await openDetail({ id: saved.item_id, revision: saved.revision });
      else {
        wipeDetail();
        showView("vault");
        await refreshVault(true);
      }
      toast("已保存");
    } catch {
      toast("保存未完成；请确认原生金库支持条目编辑");
    } finally {
      vaultBusy = false;
      if (els?.editorSave) els.editorSave.disabled = false;
    }
  }
  async function generateEditorPassword() {
    if (vaultBusy) return;
    vaultBusy = true;
    try {
      const reply = await api.runtime.sendMessage({
        type: "generate",
        options: lastState?.generatorDefaults || {},
      });
      if (!reply?.generatedPassword) throw Error("refused");
      const password = reply.generatedPassword;
      reply.generatedPassword = "";
      const target = editorInputs.find(
        (entry) =>
          entry.descriptor.name === "password" ||
          entry.descriptor.name === "card_number",
      );
      if (target) target.input.value = password;
    } catch {
      toast("无法生成密码");
    } finally {
      vaultBusy = false;
    }
  }
  function classifyDetailAction(message) {
    return api.runtime.sendMessage(message).then((reply) => {
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
      editorBack: q("#editor-back"),
      editorHeading: q("#editor-heading"),
      editorFields: q("#editor-fields"),
      customFields: q("#editor-custom-fields"),
      editorAddCustom: q("#editor-add-custom"),
      editorGenerate: q("#editor-generate"),
      editorSave: q("#editor-save"),
      editorCancel: q("#editor-cancel"),
    };
    els.searchInput.addEventListener("input", (event) => {
      searchQuery = String(event.target.value || "");
      renderVaultList();
      scheduleVaultSearch();
    });
    els.searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        searchQuery = "";
        els.searchInput.value = "";
        renderVaultList();
        scheduleVaultSearch();
      } else if (event.key === "ArrowDown") {
        event.preventDefault();
        els.vaultList.children[0]?.focus?.();
      } else if (event.key === "Enter") {
        const first = els.vaultList.children[0];
        if (first) {
          event.preventDefault();
          first.listeners?.get?.("click")?.();
        }
      }
    });
    els.searchClear.addEventListener("click", () => {
      searchQuery = "";
      els.searchInput.value = "";
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
        activeFilter = core?.validCategory(tab.dataset.filter)
          ? tab.dataset.filter
          : "all";
        if (searchTimer) clearTimeout(searchTimer);
        searchTimer = null;
        renderVaultList();
        void refreshVault(true);
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
      if (vaultBusy) return;
      vaultBusy = true;
      void api.runtime
        .sendMessage({ type: "lock" })
        .then((reply) => {
          if (reply && typeof reply === "object") {
            lastState = reply;
            render(reply);
          }
          toast("已锁定");
        })
        .catch(() => toast("锁定失败"))
        .finally(() => {
          vaultBusy = false;
          if (els) els.lockButton.disabled = !lastState?.connected;
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
  void send({ type: "state" });
  setInterval(() => void send({ type: "state" }), 500);
})();
