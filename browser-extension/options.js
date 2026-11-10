(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome;
  const core = globalThis.LocklarkCore;
  const $ = (id) => document.getElementById(id);
  function fatal(message) {
    const element = $("options-status");
    if (!element) return;
    element.textContent = message;
    element.dataset.kind = "error";
  }
  if (!core) {
    fatal("设置脚本加载失败：缺少 core.js");
    return;
  }
  if (!api?.storage?.local) {
    fatal("当前环境无法访问浏览器扩展存储");
    return;
  }
  const NAV = globalThis.navigator || {};
  const USER_AGENT = String(NAV.userAgent || "");
  const PLATFORM = String(NAV.userAgentData?.platform || NAV.platform || "");
  const IS_MAC =
    /mac|iphone|ipad|ipod/i.test(PLATFORM) ||
    /Mac OS X|Macintosh|iPhone|iPad|iPod/i.test(USER_AGENT);
  const IS_FIREFOX = /Firefox\//i.test(USER_AGENT);
  const SHORTCUT_LABELS = {
    _execute_action: "打开 Locklark 弹窗",
    autofill: "填充当前页面登录",
    "autofill-current-tab": "填充当前页面登录",
    lock: "立即锁定 Locklark",
    "lock-vault": "立即锁定 Locklark",
  };
  // Used only when the browser cannot enumerate commands (for example in tests
  // or on a transient API failure). Actual bindings always win when available.
  const DEFAULT_SHORTCUTS = [
    {
      name: "_execute_action",
      label: "打开 Locklark 弹窗",
      shortcut: IS_MAC ? "Command+Shift+Y" : "Ctrl+Shift+Y",
    },
    {
      name: "autofill",
      label: "填充当前页面登录",
      shortcut: IS_MAC ? "Command+Shift+L" : "Ctrl+Shift+L",
    },
    {
      name: "lock",
      label: "立即锁定 Locklark",
      shortcut: IS_MAC ? "Command+Shift+U" : "Ctrl+Shift+U",
    },
  ];
  const BOOLEAN_FIELDS = {
    "opt-shared-session": "sharedDesktopSession",
    "opt-biometric": "allowBiometricUnlock",
    "opt-badge-count": "showToolbarBadgeCount",
    "opt-inline-menu": "showInlineMenu",
    "opt-auto-login": "autoLogin",
    "opt-open-fill-submit": "openAndFillAutoSubmit",
    "opt-offer-identity-card": "offerFillIdentitiesAndCards",
    "opt-offer-passkeys": "offerUsePasskeys",
    "opt-paste-protection": "pasteProtection",
    "opt-otp-capture": "otpCapture",
    "opt-notifications": "notifications",
    "opt-offer-save": "offerSaveLogins",
    "opt-offer-save-passkeys": "offerSavePasskeys",
    "opt-inline-generator": "showInlineGenerator",
    "opt-generator-digits": "generatorDigits",
    "opt-generator-symbols": "generatorSymbols",
    "opt-watchtower-local": "watchtowerLocalChecks",
  };
  let settings = core.normalizeSettings({});
  let statusTimer = null;
  let saveChain = Promise.resolve();
  let revision = 0;
  function status(message, error = false) {
    const element = $("options-status");
    if (!element) return;
    element.textContent = message;
    element.dataset.kind = error ? "error" : "ok";
    if (statusTimer) clearTimeout(statusTimer);
    statusTimer = setTimeout(() => {
      statusTimer = null;
      if (element) element.textContent = "";
    }, 3000);
  }
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme =
      theme === "system" ? "light dark" : theme;
  }
  function setCheckbox(id, value) {
    const element = $(id);
    if (element) element.checked = Boolean(value);
  }
  function generatorLimits(mode) {
    if (mode === "pin") return { min: 4, max: 12 };
    if (mode === "memorable") return { min: 3, max: 12 };
    return { min: 8, max: 128 };
  }
  function syncGeneratorConstraints() {
    const length = $("opt-generator-length");
    if (!length) return;
    const limits = generatorLimits(settings.generatorDefaults.mode);
    length.min = String(limits.min);
    length.max = String(limits.max);
    length.title = `当前模式允许 ${limits.min}–${limits.max} 位`;
  }
  function render() {
    setCheckbox("opt-shared-session", settings.sharedDesktopSession);
    setCheckbox("opt-biometric", settings.allowBiometricUnlock);
    setCheckbox("opt-badge-count", settings.showToolbarBadgeCount);
    setCheckbox("opt-inline-menu", settings.showInlineMenu);
    setCheckbox("opt-auto-login", settings.autoLogin);
    setCheckbox("opt-open-fill-submit", settings.openAndFillAutoSubmit);
    setCheckbox(
      "opt-offer-identity-card",
      settings.offerFillIdentitiesAndCards,
    );
    setCheckbox("opt-offer-passkeys", settings.offerUsePasskeys);
    setCheckbox("opt-paste-protection", settings.pasteProtection);
    setCheckbox("opt-otp-capture", settings.otpCapture);
    setCheckbox("opt-offer-save", settings.offerSaveLogins);
    setCheckbox("opt-offer-save-passkeys", settings.offerSavePasskeys);
    setCheckbox("opt-inline-generator", settings.showInlineGenerator);
    setCheckbox("opt-generator-digits", settings.generatorDefaults.digits);
    setCheckbox("opt-generator-symbols", settings.generatorDefaults.symbols);
    setCheckbox("opt-watchtower-local", settings.watchtowerLocalChecks);
    const mode = $("opt-generator-mode");
    if (mode) mode.value = settings.generatorDefaults.mode;
    const length = $("opt-generator-length");
    if (length) length.value = String(settings.generatorDefaults.length);
    syncGeneratorConstraints();
    const seconds = $("opt-clipboard-seconds");
    if (seconds) seconds.value = String(settings.clipboardClearSeconds);
    const theme = $("opt-theme");
    if (theme) theme.value = settings.theme;
    const idleLock = $("opt-idle-lock");
    if (idleLock) idleLock.value = String(settings.idleLockMinutes || 0);
    renderOriginList(
      "disabled-inline-list",
      settings.disabledInlineMenuOrigins,
      "disabledInlineMenuOrigins",
    );
    renderOriginList(
      "never-save-list",
      settings.neverSaveOrigins,
      "neverSaveOrigins",
    );
    renderOverrides();
    applyTheme(settings.theme);
  }
  function renderOriginList(id, origins, key) {
    const list = $(id);
    if (!list) return;
    const listLabel =
      key === "disabledInlineMenuOrigins"
        ? "已停用快捷菜单的网站"
        : "不再提示保存登录的网站";
    list.replaceChildren();
    if (!origins.length) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "暂无网站";
      list.append(empty);
      return;
    }
    for (const origin of origins) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = origin;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.dataset.origin = origin;
      remove.textContent = "移除";
      remove.setAttribute("aria-label", `从${listLabel}中移除 ${origin}`);
      remove.addEventListener("click", () => {
        void save({
          [key]: settings[key].filter((value) => value !== origin),
        });
      });
      item.append(label, remove);
      list.append(item);
    }
  }
  function renderOverrides() {
    const list = $("login-overrides-list");
    if (!list) return;
    list.replaceChildren();
    const entries = Object.entries(settings.loginOverrides).filter(
      ([, enabled]) => enabled === false,
    );
    if (!entries.length) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "暂无已停用的登录条目";
      list.append(empty);
      return;
    }
    for (const [itemId] of entries) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = itemId;
      const reset = document.createElement("button");
      reset.type = "button";
      reset.textContent = "恢复自动提交";
      reset.setAttribute("aria-label", `恢复登录条目 ${itemId} 的自动提交`);
      reset.addEventListener("click", () => {
        const overrides = { ...settings.loginOverrides };
        delete overrides[itemId];
        void save({ loginOverrides: overrides });
      });
      item.append(label, reset);
      list.append(item);
    }
  }
  async function load() {
    const at = revision;
    try {
      const stored = await api.storage.local.get(null);
      if (at !== revision) return false;
      settings = core.normalizeSettings(stored);
      render();
      return true;
    } catch {
      if (at !== revision) return false;
      status("无法读取本机设置，已临时使用默认配置", true);
      settings = core.normalizeSettings({});
      render();
      return false;
    }
  }
  function save(patch) {
    settings = core.normalizeSettings({ ...settings, ...patch });
    revision += 1;
    const current = revision;
    const snapshot = settings;
    render();
    const task = saveChain.then(async () => {
      try {
        await api.storage.local.set(snapshot);
        if (current === revision) status("设置已保存");
      } catch {
        if (current !== revision) return;
        status("设置未能保存，已重新读取本机配置", true);
        await load();
      }
    });
    // Keep the queue alive even if an unexpected error escapes the task.
    saveChain = task.catch(() => {});
    return task;
  }
  function addOrigin(inputId, key) {
    const input = $(inputId);
    if (!input) return;
    const raw = String(input.value || "").trim();
    if (!raw) {
      status("请输入完整的 HTTPS 网站源地址", true);
      return;
    }
    let origin;
    try {
      origin = core.originFromURL(raw);
    } catch {
      status("仅支持有效的 HTTPS 网站源地址", true);
      return;
    }
    if (settings[key].includes(origin)) {
      status("该网站已在列表中", true);
      return;
    }
    if (settings[key].length >= 100) {
      status("每个列表最多保存 100 个网站", true);
      return;
    }
    input.value = "";
    void save({ [key]: [...settings[key], origin] });
  }
  function fillShortcuts(entries) {
    const list = $("shortcuts");
    if (!list) return;
    list.replaceChildren();
    for (const entry of entries) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = entry.label;
      const key = document.createElement("kbd");
      key.textContent = entry.shortcut || "未绑定（可在浏览器中设置）";
      if (entry.fallback) key.title = "默认快捷键，当前浏览器可能尚未绑定";
      item.append(label, key);
      list.append(item);
    }
  }
  async function renderShortcuts() {
    const list = $("shortcuts");
    if (!list) return;
    let commands = [];
    try {
      commands = await api.commands?.getAll?.();
    } catch {}
    const entries = [];
    const seen = new Set();
    if (Array.isArray(commands)) {
      for (const command of commands) {
        if (!command || typeof command.name !== "string") continue;
        if (seen.has(command.name)) continue;
        const label =
          SHORTCUT_LABELS[command.name] ||
          (typeof command.description === "string"
            ? command.description.trim()
            : "");
        if (!label) continue;
        seen.add(command.name);
        entries.push({
          label,
          shortcut:
            typeof command.shortcut === "string" ? command.shortcut : "",
        });
      }
    }
    if (!entries.length)
      fillShortcuts(DEFAULT_SHORTCUTS.map((entry) => ({ ...entry, fallback: true })));
    else fillShortcuts(entries);
  }
  function openShortcutSettings() {
    const url = IS_FIREFOX
      ? "about:addons"
      : "chrome://extensions/shortcuts";
    const manual = IS_FIREFOX
      ? "请手动打开 about:addons，点击齿轮并选择「管理扩展快捷键」"
      : "请手动打开 chrome://extensions/shortcuts";
    try {
      const result = api.tabs?.create?.({ url });
      if (!result) {
        status(manual, true);
        return;
      }
      if (typeof result.then === "function") {
        result.then(
          () =>
            status(
              IS_FIREFOX
                ? "已打开附加组件页，请点击齿轮并选择「管理扩展快捷键」"
                : "已打开浏览器扩展快捷键设置",
            ),
          () => status(manual, true),
        );
      } else {
        status(
          IS_FIREFOX
            ? "已打开附加组件页，请点击齿轮并选择「管理扩展快捷键」"
            : "已打开浏览器扩展快捷键设置",
        );
      }
    } catch {
      status(manual, true);
    }
  }
  function reset() {
    void save(core.normalizeSettings({}));
  }
  const nativeStatus = $("native-status");
  const nativeDetail = $("native-detail");
  async function refreshNativeStatus() {
    if (!nativeStatus) return;
    try {
      const reply = await api.runtime.sendMessage({ type: "diagnostics" });
      const connection = reply?.diagnostics?.connection;
      if (!connection) throw Error("refused");
      const stateLabel =
        {
          missing: "未找到原生宿主",
          forbidden: "浏览器拒绝了原生宿主",
          exited: "原生宿主已退出",
          timeout: "等待桌面解锁超时",
          outdated: "原生宿主版本过旧",
          error: "无法连接原生宿主",
        }[connection.state] || (connection.connected ? "已连接" : "未连接");
      nativeStatus.textContent = stateLabel + " · " + (connection.status || "");
      if (nativeDetail) {
        const capabilities = Array.isArray(connection.capabilities)
          ? connection.capabilities
          : [];
        nativeDetail.textContent = capabilities.length
          ? "原生能力：" + capabilities.join("、")
          : "尚未协商原生能力";
      }
    } catch {
      nativeStatus.textContent = "无法读取原生连接状态";
      if (nativeDetail) nativeDetail.textContent = "";
    }
  }
  $("native-refresh")?.addEventListener("click", () => void refreshNativeStatus());
  $("native-connect")?.addEventListener("click", async () => {
    if (nativeStatus) nativeStatus.textContent = "已请求连接；请在 Locklark 窗口中确认";
    try {
      await api.runtime.sendMessage({ type: "native-connect" });
    } catch {}
    setTimeout(() => void refreshNativeStatus(), 1200);
  });
  $("native-unlock")?.addEventListener("click", async () => {
    if (nativeStatus) nativeStatus.textContent = "正在请求桌面解锁…";
    try {
      const reply = await api.runtime.sendMessage({ type: "native-unlock" });
      if (nativeStatus)
        nativeStatus.textContent =
          reply?.nativeUnlock?.status || "已请求桌面解锁";
    } catch {
      if (nativeStatus) nativeStatus.textContent = "无法请求桌面解锁";
    }
  });
  void refreshNativeStatus();
  const diagnosticsButton = $("diagnostics-export");
  const diagnosticsStatus = $("diagnostics-status");
  diagnosticsButton?.addEventListener("click", async () => {
    if (!diagnosticsStatus) return;
    diagnosticsStatus.textContent = "正在生成…";
    try {
      const reply = await api.runtime.sendMessage({ type: "diagnostics" });
      if (!reply?.diagnostics) throw Error("refused");
      const blob = new Blob([JSON.stringify(reply.diagnostics, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "locklark-diagnostics.json";
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      diagnosticsStatus.textContent = "已导出诊断报告。";
    } catch {
      diagnosticsStatus.textContent = "无法导出：请先连接 Locklark 后重试。";
    }
  });
  for (const [id, key] of Object.entries(BOOLEAN_FIELDS)) {
    const element = $(id);
    if (!element) continue;
    element.addEventListener("change", () => {
      if (key === "generatorDigits")
        void save({
          generatorDefaults: {
            ...settings.generatorDefaults,
            digits: element.checked,
          },
        });
      else if (key === "generatorSymbols")
        void save({
          generatorDefaults: {
            ...settings.generatorDefaults,
            symbols: element.checked,
          },
        });
      else void save({ [key]: element.checked });
    });
  }
  const generatorMode = $("opt-generator-mode");
  if (generatorMode)
    generatorMode.addEventListener("change", () => {
      void save({
        generatorDefaults: {
          ...settings.generatorDefaults,
          mode: generatorMode.value,
        },
      });
    });
  const generatorLength = $("opt-generator-length");
  if (generatorLength)
    generatorLength.addEventListener("change", () => {
      void save({
        generatorDefaults: {
          ...settings.generatorDefaults,
          length: Number.parseInt(generatorLength.value, 10),
        },
      });
    });
  const clipboardSeconds = $("opt-clipboard-seconds");
  if (clipboardSeconds)
    clipboardSeconds.addEventListener("change", () => {
      void save({
        clipboardClearSeconds: Number.parseInt(clipboardSeconds.value, 10),
      });
    });
  const idleLock = $("opt-idle-lock");
  if (idleLock)
    idleLock.addEventListener("change", () => {
      void save({ idleLockMinutes: Number(idleLock.value) });
    });
  const theme = $("opt-theme");
  if (theme)
    theme.addEventListener("change", () => {
      void save({ theme: theme.value });
    });
  for (const [inputId, key] of [
    ["disabled-inline-input", "disabledInlineMenuOrigins"],
    ["never-save-input", "neverSaveOrigins"],
  ]) {
    const input = $(inputId);
    if (!input) continue;
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      addOrigin(inputId, key);
    });
  }
  $("add-disabled-inline")?.addEventListener("click", () =>
    addOrigin("disabled-inline-input", "disabledInlineMenuOrigins"),
  );
  $("add-never-save")?.addEventListener("click", () =>
    addOrigin("never-save-input", "neverSaveOrigins"),
  );
  $("open-shortcuts")?.addEventListener("click", openShortcutSettings);
  $("reset-settings")?.addEventListener("click", reset);
  try {
    api.commands?.onChanged?.addListener(() => void renderShortcuts());
  } catch {}
  void load();
  void renderShortcuts();
})();
