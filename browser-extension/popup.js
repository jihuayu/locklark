(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
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
  void send({ type: "state" });
  setInterval(() => void send({ type: "state" }), 500);
})();
