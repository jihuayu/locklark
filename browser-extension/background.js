/* Native secrets stay in this worker; content scripts receive metadata only. */
if (typeof importScripts === "function") importScripts("core.js");
(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome,
    core = globalThis.LocklarkCore;
  let quickFill = false,
    fillUnknown = false,
    pendingPasskey = null,
    passkeyUnknown = false,
    settings = core.normalizeSettings({}),
    autoLogin = true,
    offerSavePasskeys = true,
    offerUsePasskeys = true,
    loginOverrides = {},
    lastMatchAt = 0,
    vaultItems = [],
    detailCache = new Map(),
    pendingOpenAndFill = null,
    openAndFillTimer = null;
  function applySettings(raw) {
    settings = core.normalizeSettings(raw);
    autoLogin = settings.autoLogin;
    offerSavePasskeys = settings.offerSavePasskeys;
    offerUsePasskeys = settings.offerUsePasskeys;
    loginOverrides = settings.loginOverrides;
    return settings;
  }
  const settingsReady = (async () => {
    try {
      applySettings(await api.storage?.local?.get?.(null));
    } catch {
      // A failed preference read must fail closed for automatic submission.
      autoLogin = false;
    }
  })();
  // The options page writes storage directly (it is not a popup sender), so
  // refresh the worker's in-memory copy when settings change there.
  try {
    api.storage?.onChanged?.addListener((changes, area) => {
      if (area !== "local" || !changes || typeof changes !== "object") return;
      const patch = {};
      for (const [key, change] of Object.entries(changes))
        if (change && typeof change === "object" && "newValue" in change)
          patch[key] = change.newValue;
      if (!Object.keys(patch).length) return;
      applySettings({ ...settings, ...patch });
      updateBadge();
      rebuildContextMenus();
    });
  } catch {}
  const PASSKEY_UNKNOWN = "Passkey 创建结果未确认，请检查金库和网站后再试";
  const FILL_UNKNOWN = "登录填充结果未确认，请核实页面；不会自动重试";
  let port = null,
    capability = "",
    context = null,
    rows = [],
    status = "未连接",
    pending = null,
    pendingOTP = null,
    otpCancellation = null,
    otpUnknown = false,
    epoch = 0,
    unconfirmedSave = false;
  const OTP_UNKNOWN = "验证码填充结果未确认，请核实页面";
  const SAVE_UNKNOWN = "结果未确认，请在金库核实，勿重复保存";
  const calls = new Map(),
    retired = new Set(),
    epochWaiters = new Set();
  function advanceEpoch() {
    epoch++;
    for (const abort of [...epochWaiters]) abort();
  }
  function bounded(promise, generation, milliseconds = 1500) {
    return new Promise((resolve, reject) => {
      if (generation !== epoch) {
        reject(Error("refused"));
        return;
      }
      let done = false,
        timer;
      const finish = (ok, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        epochWaiters.delete(abort);
        if (ok) resolve(value);
        else reject(Error("refused"));
      };
      const abort = () => finish(false);
      epochWaiters.add(abort);
      timer = setTimeout(abort, milliseconds);
      Promise.resolve(promise).then(
        (value) => finish(true, value),
        () => finish(false),
      );
    });
  }
  function id() {
    return [...crypto.getRandomValues(new Uint8Array(16))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  function clearPendingOpenAndFill() {
    pendingOpenAndFill = null;
    if (openAndFillTimer) clearTimeout(openAndFillTimer);
    openAndFillTimer = null;
  }
  function publicItem(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    if (
      !/^[a-f0-9]{32}$/.test(item.id || "") ||
      !/^[a-f0-9]{64}$/.test(item.revision || "") ||
      typeof item.title !== "string" ||
      item.title.length > 1024
    )
      return null;
    const category = core.normalizeCategory(item.category) || "login";
    const urls = Array.isArray(item.urls)
      ? item.urls
          .slice(0, 20)
          .filter((url) => typeof url === "string" && url.length <= 8192)
      : [];
    const tags = Array.isArray(item.tags)
      ? item.tags
          .slice(0, 50)
          .filter((tag) => typeof tag === "string" && tag.length <= 128)
      : [];
    return {
      id: item.id,
      revision: item.revision,
      category,
      title: item.title,
      subtitle:
        typeof item.subtitle === "string"
          ? item.subtitle.slice(0, 1024)
          : typeof item.username === "string"
            ? item.username.slice(0, 1024)
            : "",
      urls,
      tags,
      favorite: item.favorite === true,
      state: ["active", "archived", "trashed"].includes(item.state)
        ? item.state
        : "active",
      has_otp: item.has_otp === true,
      updated_at:
        typeof item.updated_at === "string"
          ? item.updated_at.slice(0, 64)
          : "",
    };
  }
  function boundedString(value, length = 16384) {
    return typeof value === "string" ? value.slice(0, length) : "";
  }
  function publicDetail(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const meta = publicItem(item);
    if (!meta) return null;
    const fields = core.flattenItemFields(item);
    const sections = Array.isArray(item.sections)
      ? item.sections.slice(0, 20).map((section) => ({
          title: boundedString(section?.title, 256),
          fields: core
            .flattenItemFields({ fields: section?.fields || [] })
            .slice(0, 100),
        }))
      : [];
    return {
      ...meta,
      notes: boundedString(item.notes, 65536),
      username: boundedString(item.username),
      password: boundedString(item.password),
      otp_secret: boundedString(item.otp_secret),
      otp_code: /^(?:[0-9]{6}|[0-9]{8})$/.test(item.otp_code || "")
        ? item.otp_code
        : "",
      otp_remaining_ms:
        Number.isSafeInteger(item.otp_remaining_ms) &&
        item.otp_remaining_ms >= 0
          ? Math.min(30000, item.otp_remaining_ms)
          : 0,
      fields,
      sections,
    };
  }
  function currentSiteFlags() {
    if (!context?.origin)
      return { disabledInline: false, neverSave: false };
    return {
      disabledInline: settings.disabledInlineMenuOrigins.includes(
        context.origin,
      ),
      neverSave: settings.neverSaveOrigins.includes(context.origin),
    };
  }
  function snapshot() {
    const site = currentSiteFlags();
    return {
      connected: !!capability,
      locked: !capability,
      autoLogin,
      quickFill,
      loginOverrides,
      offerSavePasskeys,
      offerUsePasskeys,
      showInlineMenu: settings.showInlineMenu,
      showToolbarBadgeCount: settings.showToolbarBadgeCount,
      openAndFillAutoSubmit: settings.openAndFillAutoSubmit,
      disabledInlineMenu: site.disabledInline,
      neverSave: site.neverSave,
      clipboardClearSeconds: settings.clipboardClearSeconds,
      theme: settings.theme,
      status:
        status +
        (otpUnknown && !status.includes(OTP_UNKNOWN)
          ? " · " + OTP_UNKNOWN
          : "") +
        (fillUnknown && !status.includes(FILL_UNKNOWN)
          ? " · " + FILL_UNKNOWN
          : "") +
        (passkeyUnknown && !status.includes(PASSKEY_UNKNOWN)
          ? " · " + PASSKEY_UNKNOWN
          : ""),
      candidates: rows.map((r) => ({
        id: r.id,
        title: r.title,
        revision: r.revision,
      })),
      vaultItems: vaultItems.map((item) => ({ ...item })),
      pending: !!pending || !!pendingOTP || !!pendingPasskey,
      otpPending: !!pendingOTP,
      saveBlocked: unconfirmedSave,
      origin: context?.origin || "",
    };
  }
  function setBadge(text, color, title) {
    try {
      api.action?.setBadgeText?.({ text });
      if (color) api.action?.setBadgeBackgroundColor?.({ color });
      if (title) api.action?.setTitle?.({ title });
    } catch {}
  }
  function updateBadge() {
    if (!api.action) return;
    if (unconfirmedSave || otpUnknown || fillUnknown || passkeyUnknown) {
      setBadge("!", "#dc2626", "Locklark — 存在未确认操作");
      return;
    }
    if (!capability) {
      setBadge("L", "#d97706", "Locklark — 已锁定");
      return;
    }
    if (
      settings.showToolbarBadgeCount !== false &&
      rows.length > 0 &&
      context?.origin
    ) {
      const count = rows.length > 99 ? "99+" : String(rows.length);
      setBadge(count, "#0f766e", `Locklark — ${rows.length} 个匹配登录`);
      return;
    }
    setBadge("", "#0f766e", "Locklark — 已解锁");
  }
  function clear() {
    if (pending?.injectionStarted) fillUnknown = true;
    if (pendingPasskey?.create) passkeyUnknown = true;
    pendingPasskey = null;
    quickFill = false;
    if (pendingOTP?.ackSent || pendingOTP?.injectionStarted) otpUnknown = true;
    otpCancellation = null;
    capability = "";
    context = null;
    rows = [];
    pending = null;
    pendingOTP = null;
    vaultItems = [];
    detailCache.clear();
    clearPendingOpenAndFill();
    advanceEpoch();
    for (const [requestId, c] of calls) {
      retired.add(requestId);
      clearTimeout(c.timer);
      c.reject(Error("refused"));
    }
    calls.clear();
    updateBadge();
    rebuildContextMenus();
  }
  function disconnect() {
    const p = port;
    port = null;
    clear();
    if (p) p.disconnect();
  }
  function disconnectWithStatus(message) {
    disconnect();
    status = unconfirmedSave
      ? SAVE_UNKNOWN
      : otpUnknown
        ? message + " · " + OTP_UNKNOWN
        : message;
  }
  function menuCreate(options) {
    try {
      api.contextMenus?.create?.(options);
    } catch {}
  }
  function menuRemoveAll() {
    try {
      api.contextMenus?.removeAll?.();
    } catch {}
  }
  function menuItems(category) {
    return vaultItems
      .filter((item) => item.category === category)
      .slice(0, 10);
  }
  function rebuildContextMenus() {
    if (!api.contextMenus || typeof api.contextMenus.create !== "function")
      return;
    menuRemoveAll();
    menuCreate({
      id: "locklark-root",
      title: "Locklark",
      contexts: ["page", "editable"],
    });
    if (!capability) {
      menuCreate({
        id: "locklark-connect",
        parentId: "locklark-root",
        title: "解锁 Locklark…",
        contexts: ["page", "editable"],
      });
      menuCreate({
        id: "locklark-options",
        parentId: "locklark-root",
        title: "扩展设置…",
        contexts: ["page", "editable"],
      });
      return;
    }
    for (const [id, title, category] of [
      ["fill-login", "填充登录", "login"],
      ["fill-identity", "填充身份信息", "identity"],
      ["fill-card", "填充银行卡", "card"],
    ]) {
      menuCreate({
        id,
        parentId: "locklark-root",
        title,
        contexts: ["page", "editable"],
      });
      const matches =
        category === "login"
          ? rows.slice(0, 10).map((row) => ({
              id: row.id,
              revision: row.revision,
              title: row.title,
            }))
          : menuItems(category);
      if (!matches.length)
        menuCreate({
          id: id + "-empty",
          parentId: id,
          title:
            category === "login"
              ? "（当前网站无匹配登录）"
              : "（暂无可用条目）",
          enabled: false,
          contexts: ["page", "editable"],
        });
      for (const item of matches)
        menuCreate({
          id: `${id}:${item.id}:${item.revision}`,
          parentId: id,
          title: (item.title || "（无标题）").slice(0, 64),
          contexts: ["page", "editable"],
        });
    }
    menuCreate({
      id: "generate-password",
      parentId: "locklark-root",
      title: "生成并填充新密码",
      contexts: ["editable"],
    });
    menuCreate({
      id: "save-login",
      parentId: "locklark-root",
      title: "保存当前页面登录",
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "context-separator-1",
      parentId: "locklark-root",
      type: "separator",
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "locklark-toggle-site-inline",
      parentId: "locklark-root",
      title: "在此网站禁用内联菜单",
      type: "checkbox",
      checked: currentSiteFlags().disabledInline,
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "lock-vault",
      parentId: "locklark-root",
      title: "立即锁定 Locklark",
      contexts: ["all"],
    });
    menuCreate({
      id: "locklark-options",
      parentId: "locklark-root",
      title: "扩展设置…",
      contexts: ["all"],
    });
  }
  function openOptions() {
    try {
      const result = api.runtime.openOptionsPage?.();
      if (result && typeof result.catch === "function") result.catch(() => {});
    } catch {}
  }
  function contextMenuClicked(info) {
    const id = typeof info?.menuItemId === "string" ? info.menuItemId : "";
    if (id === "locklark-connect") {
      void connect();
      return;
    }
    if (id === "locklark-options") {
      openOptions();
      return;
    }
    if (id === "lock-vault") {
      void lockVault();
      return;
    }
    if (id === "save-login") {
      void save();
      return;
    }
    if (id === "generate-password") {
      void generateAndFill();
      return;
    }
    if (id === "locklark-toggle-site-inline") {
      void toggleSiteInline();
      return;
    }
    const [kind, itemId, revision] = id.split(":");
    if (!/^[a-f0-9]{32}$/.test(itemId || "")) return;
    if (!/^[a-f0-9]{64}$/.test(revision || "")) return;
    if (kind === "fill-login") {
      const row = rows.find(
        (candidate) =>
          candidate.id === itemId && candidate.revision === revision,
      );
      if (row) void fill(itemId, revision);
      return;
    }
    if (kind === "fill-identity") {
      void fillItemCategory(itemId, revision, "identity");
      return;
    }
    if (kind === "fill-card") {
      void fillItemCategory(itemId, revision, "card");
    }
  }
  function commandInvoked(command) {
    if (command === "autofill" || command === "autofill-current-tab") {
      void autofillActiveTab();
      return;
    }
    if (command === "lock" || command === "lock-vault") lockVault();
  }
  try {
    api.commands?.onCommand?.addListener(commandInvoked);
  } catch {}
  try {
    api.contextMenus?.onClicked?.addListener(contextMenuClicked);
  } catch {}
  try {
    api.runtime.onInstalled?.addListener(() => {
      rebuildContextMenus();
      updateBadge();
    });
  } catch {}
  function startCall(type, requestId, timeout) {
    let resolve, reject;
    const promise = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const timer = setTimeout(() => {
      calls.delete(requestId);
      reject(Error("refused"));
      disconnectWithStatus("连接或请求已过期，请重新连接");
    }, timeout);
    calls.set(requestId, { resolve, reject, timer, type });
    return promise;
  }
  function request(type, fields = {}, timeout = 35000, requestId = id()) {
    if (!port) return Promise.reject(Error("refused"));
    const promise = startCall(type, requestId, timeout);
    try {
      port.postMessage({ v: 1, id: requestId, type, ...fields });
    } catch {
      const call = calls.get(requestId);
      if (call) {
        clearTimeout(call.timer);
        calls.delete(requestId);
        call.reject(Error("refused"));
      }
    } finally {
      if (Object.hasOwn(fields, "username")) fields.username = "";
      if (Object.hasOwn(fields, "password")) fields.password = "";
      if (Object.hasOwn(fields, "item_json")) fields.item_json = "";
    }
    return promise;
  }
  async function capture() {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    if (
      tabs.length !== 1 ||
      !Number.isSafeInteger(tabs[0].id) ||
      tabs[0].id < 1 ||
      !Number.isSafeInteger(tabs[0].windowId) ||
      tabs[0].windowId < 1
    )
      throw Error("refused");
    const tab = tabs[0],
      origin = core.originFromURL(tab.url);
    const results = await api.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: core.probe,
    });
    if (
      results.length !== 1 ||
      results[0].frameId !== 0 ||
      typeof results[0].documentId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(results[0].documentId) ||
      !results[0].result?.top ||
      results[0].result.origin !== origin
    )
      throw Error("refused");
    const again = await api.tabs.query({ active: true, currentWindow: true });
    if (
      again.length !== 1 ||
      again[0].id !== tab.id ||
      again[0].windowId !== tab.windowId ||
      core.originFromURL(again[0].url) !== origin
    )
      throw Error("refused");
    return {
      tabId: tab.id,
      windowId: tab.windowId,
      origin,
      documentId: results[0].documentId,
    };
  }
  function fields(c) {
    return {
      capability,
      origin: c.origin,
      tab_id: c.tabId,
      document_id: c.documentId,
    };
  }
  async function current(expected) {
    const now = await capture();
    if (!core.sameContext(expected, now)) throw Error("refused");
  }
  async function connect() {
    disconnect();
    unconfirmedSave = false;
    retired.clear();
    status = "请在原生窗口解锁并确认连接";
    const p = api.runtime.connectNative("org.locklark.browser");
    port = p;
    p.onDisconnect.addListener(() => {
      if (port !== p) return;
      port = null;
      const uncertain = unconfirmedSave;
      clear();
      status = uncertain
        ? "结果未确认，请在金库核实，勿重复保存"
        : "原生连接已断开，请重新连接";
      if (otpUnknown) status += " · " + OTP_UNKNOWN;
      void api.runtime.lastError;
    });
    p.onMessage.addListener((message) => {
      if (port !== p) {
        if (message && typeof message === "object" && "code" in message)
          message.code = "";
        return;
      }
      if (!core.validResponse(message)) {
        if (message && typeof message === "object" && "code" in message)
          message.code = "";
        disconnectWithStatus("原生协议错误，请重新连接");
        return;
      }
      if (message?.type === "locked") {
        const uncertain = unconfirmedSave;
        clear();
        status = uncertain
          ? "原生金库已锁定 · 结果未确认，请在金库核实，勿重复保存"
          : "原生金库已锁定，请重新连接并配对";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        return;
      }
      if (message.type === "unpaired") {
        const uncertain = unconfirmedSave;
        clear();
        status = uncertain
          ? "结果未确认，请在金库核实，勿重复保存"
          : "扩展连接已到期，请重新连接并配对";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        return;
      }
      if (!message || message.v !== 1 || typeof message.id !== "string")
        return disconnectWithStatus("原生协议错误，请重新连接");
      const call = calls.get(message.id);
      if (!call) {
        if ("code" in message) message.code = "";
        if (retired.delete(message.id)) return;
        return disconnectWithStatus("原生协议错误，请重新连接");
      }
      calls.delete(message.id);
      clearTimeout(call.timer);
      if (message.type === "error") {
        const refusal = Error("refused");
        refusal.knownRefusal = true;
        call.reject(refusal);
        return;
      }
      const expected = {
        hello: "paired",
        match: "candidates",
        fill: "fill",
        cancel: "cancelled",
        "cancel-save": "cancelled",
        "save-new": "save-ready",
        "save-update": "save-ready",
        "commit-ready": "saved",
        otp: "otp-ready",
        "otp-ack": "otp-fill",
        "cancel-otp": "cancelled",
        "passkey-create": "passkey-result",
        "passkey-get": "passkey-result",
        "vault-search": "vault-items",
        "vault-list": "vault-items",
        "item-get": "item-detail",
        "item-save": "saved",
        "item-state": "saved",
        generate: "generated",
        "fill-item": "fill-fields",
      }[call.type];
      if (
        message.type === "unknown" &&
        [
          "commit-ready",
          "cancel-save",
          "cancel-otp",
          "passkey-create",
          "passkey-get",
        ].includes(call.type)
      ) {
        call.resolve(message);
        return;
      }
      if (message.type !== expected) {
        if ("code" in message) message.code = "";
        call.reject(Error("refused"));
        disconnectWithStatus("原生协议错误，请重新连接");
        return;
      }
      call.resolve(message);
    });
    const generation = epoch;
    try {
      const response = await request("hello", {}, 65000);
      if (generation !== epoch) throw Error("refused");
      if (!/^[a-f0-9]{32}$/.test(response.capability)) throw Error("refused");
      capability = response.capability;
      quickFill = response.quick_fill === true;
      status = "已连接，请读取当前网站候选";
      updateBadge();
      rebuildContextMenus();
    } catch {
      if (port === p && generation === epoch) {
        disconnect();
        status = "连接未获批准或已过期";
      }
    }
  }
  async function match() {
    if (!capability || pending || pendingOTP || pendingPasskey)
      throw Error("refused");
    rows = [];
    context = null;
    updateBadge();
    const generation = epoch,
      c = await capture();
    await current(c);
    if (generation !== epoch) throw Error("refused");
    const response = await request("match", fields(c));
    if (generation !== epoch) throw Error("refused");
    await current(c);
    if (generation !== epoch) throw Error("refused");
    if (
      !Array.isArray(response.candidates) &&
      response.candidates !== undefined
    )
      throw Error("refused");
    const next = response.candidates || [];
    if (
      next.length > 100 ||
      next.some(
        (r) =>
          !r ||
          !/^[a-f0-9]{32}$/.test(r.id) ||
          !/^[a-f0-9]{64}$/.test(r.revision) ||
          typeof r.title !== "string" ||
          r.title.length > 16384 ||
          r.state !== "active",
      )
    )
      throw Error("refused");
    context = c;
    rows = next;
    status = `${rows.length} 个当前网站登录`;
    updateBadge();
    rebuildContextMenus();
  }
  async function fill(itemId, revision) {
    const row = rows.find((r) => r.id === itemId && r.revision === revision),
      c = context,
      generation = epoch;
    if (!capability || pending || pendingOTP || pendingPasskey || !row || !c)
      throw Error("refused");
    const intent = { itemId, revision, tabId: c.tabId, windowId: c.windowId };
    pending = intent;
    status = quickFill
      ? "正在填充所选账号"
      : "请在原生窗口核对来源、条目与修订并批准";
    let response;
    try {
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      response = await request("fill", {
        ...fields(c),
        item_id: itemId,
        revision,
      });
      if (generation !== epoch) throw Error("refused");
      await bounded(current(c), generation);
      if (generation !== epoch) throw Error("refused");
      if (
        typeof response.username !== "string" ||
        typeof response.password !== "string" ||
        response.username.length > 16384 ||
        response.password.length > 16384
      )
        throw Error("refused");
      await settingsReady;
      await bounded(current(c), generation);
      const submit = autoLogin && loginOverrides[itemId] !== false;
      intent.injectionStarted = true;
      const results = await bounded(
        api.scripting.executeScript({
          target: { tabId: c.tabId, documentIds: [c.documentId] },
          func: core.fillDocument,
          args: [
            c.origin,
            response.username,
            response.password,
            Date.now() + 1500,
            false,
            submit,
          ],
        }),
        generation,
      );
      if (
        results.length !== 1 ||
        results[0].frameId !== 0 ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.injectionStarted = false;
      fillUnknown = false;
      status = submit
        ? "已请求填充及登录；请核实网站结果"
        : "本次已请求填充；未自动提交";
    } catch {
      if (generation === epoch && pending === intent) {
        fillUnknown = intent.injectionStarted === true;
        status = fillUnknown ? FILL_UNKNOWN : "本次填充未完成；未自动重试";
      }
    } finally {
      if (response) {
        response.username = "";
        response.password = "";
      }
      if (generation === epoch && pending === intent) {
        pending = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function clearCapture(results) {
    if (Array.isArray(results))
      for (const row of results) {
        if (row?.result && typeof row.result === "object") {
          row.result.username = "";
          row.result.password = "";
        }
      }
  }
  async function captureValues(c, generation) {
    const promise = api.scripting.executeScript({
      target: { tabId: c.tabId, documentIds: [c.documentId] },
      func: core.fillDocument,
      args: [c.origin, "", "", Date.now() + 1500, true],
    });
    let live = true;
    promise.then(
      (rows) => {
        if (!live || generation !== epoch) clearCapture(rows);
      },
      () => {},
    );
    try {
      const result = await bounded(promise, generation);
      if (
        result.length !== 1 ||
        result[0].frameId !== 0 ||
        result[0].documentId !== c.documentId ||
        !result[0].result ||
        typeof result[0].result !== "object"
      ) {
        clearCapture(result);
        throw Error("refused");
      }
      return result;
    } finally {
      live = false;
    }
  }
  async function verifySaveDocument(c, generation) {
    const active = await bounded(
      api.tabs.query({ active: true, currentWindow: true }),
      generation,
    );
    if (
      active.length !== 1 ||
      active[0].id !== c.tabId ||
      active[0].windowId !== c.windowId ||
      core.originFromURL(active[0].url) !== c.origin
    )
      throw Error("refused");
    const probe = await bounded(
      api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.probe,
      }),
      generation,
    );
    if (
      probe.length !== 1 ||
      probe[0].frameId !== 0 ||
      probe[0].documentId !== c.documentId ||
      !probe[0].result?.top ||
      probe[0].result.origin !== c.origin
    )
      throw Error("refused");
    const final = await bounded(
      api.tabs.query({ active: true, currentWindow: true }),
      generation,
    );
    if (
      final.length !== 1 ||
      final[0].id !== c.tabId ||
      final[0].windowId !== c.windowId ||
      core.originFromURL(final[0].url) !== c.origin
    )
      throw Error("refused");
  }
  async function save(itemId, revision) {
    const generation = epoch,
      previous = context;
    if (
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey ||
      unconfirmedSave
    )
      throw Error("refused");
    if (itemId && !rows.some((r) => r.id === itemId && r.revision === revision))
      throw Error("refused");
    const intent = {
      kind: "save",
      requestId: id(),
      tabId: null,
      windowId: null,
      commitStarted: false,
    };
    pending = intent;
    status = "正在捕获当前登录";
    let captured;
    try {
      const c = await bounded(capture(), generation);
      intent.tabId = c.tabId;
      intent.windowId = c.windowId;
      if (itemId && !core.sameContext(c, previous)) throw Error("refused");
      await verifySaveDocument(c, generation);
      captured = await captureValues(c, generation);
      await verifySaveDocument(c, generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      const values = captured[0].result;
      if (
        typeof values.username !== "string" ||
        typeof values.password !== "string" ||
        values.password.length === 0 ||
        !values.username.isWellFormed() ||
        !values.password.isWellFormed() ||
        new TextEncoder().encode(values.username).length > 16384 ||
        new TextEncoder().encode(values.password).length > 16384
      )
        throw Error("refused");
      const fieldsToSend = {
        ...fields(c),
        window_id: c.windowId,
        username: values.username,
        password: values.password,
      };
      if (itemId) {
        fieldsToSend.item_id = itemId;
        fieldsToSend.revision = revision;
      }
      const waiting = request(
        itemId ? "save-update" : "save-new",
        fieldsToSend,
        35000,
        intent.requestId,
      );
      clearCapture(captured);
      captured = null;
      status = "请在原生窗口核对并批准保存登录";
      const ready = await waiting;
      if (generation !== epoch || pending !== intent) throw Error("refused");
      status = "已批准，正在核对当前页面";
      await bounded(verifySaveDocument(c, generation), generation, 1500);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.commitStarted = true;
      unconfirmedSave = true;
      status = "正在保存";
      const result = await request(
        "commit-ready",
        { capability, request_id: intent.requestId, nonce: ready.nonce },
        15000,
      );
      if (generation !== epoch || pending !== intent) throw Error("refused");
      if (result.type === "saved") unconfirmedSave = false;
      status =
        result.type === "saved"
          ? "已保存"
          : "结果未确认，请在金库核实，勿重复保存";
    } catch (error) {
      if (generation === epoch && pending === intent) {
        if (error.knownRefusal) unconfirmedSave = false;
        status =
          intent.commitStarted && !error.knownRefusal
            ? "结果未确认，请在金库核实，勿重复保存"
            : "未保存";
        if (capability)
          void request("cancel-save", {
            capability,
            request_id: intent.requestId,
          }).catch(() => {});
      }
    } finally {
      clearCapture(captured);
      if (generation === epoch && pending === intent) {
        pending = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function validOTPProbe(value, c) {
    return (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).sort().join(",") ===
        "now,origin,timeOrigin,top,wall" &&
      value.top === true &&
      value.origin === c.origin &&
      Number.isFinite(value.timeOrigin) &&
      value.timeOrigin > 0 &&
      Number.isFinite(value.now) &&
      value.now >= 0 &&
      Number.isSafeInteger(value.wall) &&
      value.wall > 0
    );
  }
  async function otpProbe(c, generation, remaining = () => 1500) {
    await bounded(current(c), generation, remaining());
    const results = await bounded(
      api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.otpDocument,
        args: [c.origin, "probe"],
      }),
      generation,
      remaining(),
    );
    if (
      results.length !== 1 ||
      results[0].frameId !== 0 ||
      results[0].documentId !== c.documentId ||
      !validOTPProbe(results[0].result, c)
    )
      throw Error("refused");
    await bounded(current(c), generation, remaining());
    return results[0].result;
  }
  function cancelOTP() {
    const intent = pendingOTP;
    if (!intent) return;
    pendingOTP = null;
    context = null;
    rows = [];
    advanceEpoch();
    const cancelStatus = intent.sent ? OTP_UNKNOWN : "本次验证码填充已取消";
    const cancellation = { generation: epoch, status: cancelStatus };
    otpCancellation = cancellation;
    otpUnknown = intent.sent;
    status = cancelStatus;
    const ownsCancellationView = () =>
      !pending && !pendingOTP && !context && status === cancellation.status;
    updateBadge();
    rebuildContextMenus();
    if (!intent.sent || !capability) return;
    // Host cancellation cannot retract an injection already submitted to the
    // browser, even if its executeScript promise has not settled yet.
    void request("cancel-otp", {
      capability,
      request_id: intent.requestId,
    }).then(
      (result) => {
        if (
          otpCancellation !== cancellation ||
          epoch !== cancellation.generation
        )
          return;
        const confirmed =
          result.type === "cancelled" && !intent.injectionStarted;
        otpUnknown = !confirmed;
        // A later ordinary fill/save/match owns its own status. The C result
        // still resolves the historical OTP uncertainty without replacing it.
        if (ownsCancellationView())
          status = confirmed ? "本次验证码填充已取消" : OTP_UNKNOWN;
      },
      () => {
        if (
          otpCancellation === cancellation &&
          epoch === cancellation.generation
        ) {
          otpUnknown = true;
          if (ownsCancellationView()) status = OTP_UNKNOWN;
        }
      },
    );
  }
  async function otp(itemId, revision) {
    const row = rows.find((r) => r.id === itemId && r.revision === revision);
    if (
      !row ||
      !context ||
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    const c = context,
      generation = epoch;
    const intent = {
      requestId: id(),
      tabId: c.tabId,
      windowId: c.windowId,
      sent: false,
      ackSent: false,
      injectionStarted: false,
    };
    otpCancellation = null;
    otpUnknown = false;
    pendingOTP = intent;
    status = "请在原生窗口批准本次验证码填充";
    let response = null,
      live = true;
    try {
      await otpProbe(c, generation);
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      intent.sent = true;
      const challenge = await request(
        "otp",
        {
          ...fields(c),
          window_id: c.windowId,
          item_id: itemId,
          revision,
        },
        35000,
        intent.requestId,
      );
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      // This single background deadline starts BEFORE the final probe. The page
      // carries its own clock sample; clocks from different worlds never mix.
      const started = performance.now(),
        wall = Date.now();
      const remaining = () => {
        const now = performance.now(),
          elapsed = now - started,
          wallNow = Date.now();
        if (
          !Number.isFinite(elapsed) ||
          elapsed < 0 ||
          elapsed >= 1500 ||
          wallNow < wall ||
          wallNow >= wall + 1500
        )
          throw Error("refused");
        return Math.max(1, Math.min(1500 - elapsed, wall + 1500 - wallNow));
      };
      const timing = await otpProbe(c, generation, remaining);
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      const ackTimeout = remaining();
      intent.ackSent = true;
      const reply = request(
        "otp-ack",
        {
          capability,
          request_id: intent.requestId,
          nonce: challenge.nonce,
        },
        ackTimeout,
      );
      challenge.nonce = "";
      // A response which arrives after navigation/timeout is never retained.
      reply.then(
        (value) => {
          if (!live || generation !== epoch || pendingOTP !== intent)
            value.code = "";
        },
        (error) => {
          intent.knownRefusal = error.knownRefusal === true;
        },
      );
      response = await bounded(reply, generation, remaining());
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      await bounded(current(c), generation, remaining());
      const args = [c.origin, "fill", response.code, timing];
      response.code = "";
      let injection;
      try {
        remaining();
        intent.injectionStarted = true;
        injection = api.scripting.executeScript({
          target: { tabId: c.tabId, documentIds: [c.documentId] },
          func: core.otpDocument,
          args,
        });
      } finally {
        args[2] = "";
      }
      const results = await bounded(injection, generation, remaining());
      remaining();
      if (
        generation !== epoch ||
        pendingOTP !== intent ||
        results.length !== 1 ||
        results[0].frameId !== 0 ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      status = "本次已请求填充验证码；未自动提交";
    } catch {
      if (generation === epoch && pendingOTP === intent) {
        otpUnknown =
          intent.injectionStarted || (intent.ackSent && !intent.knownRefusal);
        status = otpUnknown ? OTP_UNKNOWN : "本次验证码填充被拒绝或已过期";
        if (capability)
          void request("cancel-otp", {
            capability,
            request_id: intent.requestId,
          }).catch(() => {});
      }
    } finally {
      live = false;
      if (response) response.code = "";
      if (generation === epoch && pendingOTP === intent) {
        pendingOTP = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function cancelContext() {
    if (pendingPasskey) {
      if (pendingPasskey.create) passkeyUnknown = true;
      pendingPasskey = null;
      advanceEpoch();
      rows = [];
      context = null;
      if (capability) void request("cancel", { capability }).catch(() => {});
      updateBadge();
      rebuildContextMenus();
      return;
    }
    if (pending?.injectionStarted) fillUnknown = true;
    if (pendingOTP) {
      cancelOTP();
      return;
    }
    if (!context && !pending) {
      updateBadge();
      rebuildContextMenus();
      return;
    }
    const intent = pending;
    context = null;
    rows = [];
    pending = null;
    advanceEpoch();
    status = unconfirmedSave
      ? "结果未确认，请在金库核实，勿重复保存"
      : "页面或活动标签已变化，请重新读取候选";
    if (capability)
      void request(
        intent?.kind === "save" ? "cancel-save" : "cancel",
        intent?.kind === "save"
          ? { capability, request_id: intent.requestId }
          : { capability },
      ).catch(() => {});
    updateBadge();
    rebuildContextMenus();
  }
  api.tabs.onActivated.addListener(() => {
    cancelContext();
    updateBadge();
    rebuildContextMenus();
  });
  api.tabs.onUpdated.addListener((tabId, change) => {
    if (
      (context?.tabId === tabId ||
        pending?.tabId === tabId ||
        pendingOTP?.tabId === tabId ||
        pendingPasskey?.tabId === tabId) &&
      ("url" in change || change.status === "loading")
    )
      cancelContext();
    if ("url" in change || change.status === "complete") {
      updateBadge();
      rebuildContextMenus();
    }
    void processOpenAndFill(tabId, change);
  });
  api.windows.onFocusChanged.addListener((windowId) => {
    updateBadge();
    if (windowId === api.windows.WINDOW_ID_NONE) return;
    const bound =
      pendingPasskey?.windowId ??
      pendingOTP?.windowId ??
      pending?.windowId ??
      context?.windowId;
    if (
      (pendingPasskey || pendingOTP || pending || context) &&
      (bound == null || bound !== windowId)
    )
      cancelContext();
  });
  function lockVault() {
    const p = port,
      cap = capability;
    if (p && cap) {
      try {
        p.postMessage({ v: 1, id: id(), type: "lock", capability: cap });
      } catch {}
    }
    disconnectWithStatus("已锁定 Locklark");
    updateBadge();
    rebuildContextMenus();
  }
  async function setSiteSettings(disabledInline, neverSave) {
    if (!context?.origin) throw Error("refused");
    const origin = context.origin;
    const next = core.normalizeSettings({
      ...settings,
      disabledInlineMenuOrigins:
        typeof disabledInline === "boolean"
          ? disabledInline
            ? [...settings.disabledInlineMenuOrigins, origin]
            : settings.disabledInlineMenuOrigins.filter(
                (value) => value !== origin,
              )
          : settings.disabledInlineMenuOrigins,
      neverSaveOrigins:
        typeof neverSave === "boolean"
          ? neverSave
            ? [...settings.neverSaveOrigins, origin]
            : settings.neverSaveOrigins.filter((value) => value !== origin)
          : settings.neverSaveOrigins,
    });
    await api.storage.local.set({
      disabledInlineMenuOrigins: next.disabledInlineMenuOrigins,
      neverSaveOrigins: next.neverSaveOrigins,
    });
    settings = next;
    status = "网站设置已更新";
    updateBadge();
    rebuildContextMenus();
  }
  async function toggleSiteInline() {
    if (!context?.origin) {
      status = "请先读取当前网站候选";
      return;
    }
    try {
      await setSiteSettings(!currentSiteFlags().disabledInline, undefined);
    } catch {
      status = "网站设置未保存";
    }
  }
  async function autofillActiveTab() {
    if (!capability) {
      status = "请先解锁 Locklark";
      updateBadge();
      return;
    }
    try {
      await match();
      if (rows.length === 0) {
        status = "当前网站无匹配登录";
      } else if (rows.length === 1) {
        await fill(rows[0].id, rows[0].revision);
      } else {
        const tabs = await api.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (tabs.length === 1 && Number.isSafeInteger(tabs[0].id))
          await api.tabs
            .sendMessage?.(tabs[0].id, {
              type: "locklark:open-inline-menu",
            })
            .catch(() => {});
        status = `发现 ${rows.length} 个匹配登录，请在页面中选择`;
      }
    } catch {
      status = "自动填充未完成；请确认原生连接和当前 HTTPS 页面";
    }
    updateBadge();
    rebuildContextMenus();
  }
  async function generatePasswordValue(rawOptions) {
    const options = core.normalizeGeneratorDefaults(rawOptions);
    if (capability) {
      try {
        const response = await request(
          "generate",
          { capability, options: JSON.stringify(options) },
          12000,
        );
        return response.password;
      } catch {}
    }
    return core.generatePassword(options);
  }
  async function generateAndFill() {
    if (!capability) {
      status = "请先解锁 Locklark";
      updateBadge();
      return;
    }
    let password = "";
    try {
      const options = settings.generatorDefaults;
      try {
        const response = await request(
          "generate",
          { capability, options: JSON.stringify(options) },
          12000,
        );
        password = response.password;
      } catch {
        password = core.generatePassword(options);
      }
      const c = await capture();
      await current(c);
      const results = await api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.fillGeneratedPasswordDocument,
        args: [c.origin, password, Date.now() + 1500],
      });
      if (
        results.length !== 1 ||
        results[0].frameId !== 0 ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      status = "已生成并填充新密码";
    } catch {
      status = "生成密码未完成；请确认当前密码输入框";
    } finally {
      password = "";
      updateBadge();
    }
  }
  async function fillItemCategory(itemId, revision, category) {
    if (
      !capability ||
      !vaultItems.some(
        (item) => item.id === itemId && item.revision === revision,
      )
    ) {
      status = "条目已变化，请刷新后重试";
      return;
    }
    try {
      const c = await capture();
      await current(c);
      const response = await request(
        "fill-item",
        {
          ...fields(c),
          item_id: itemId,
          revision,
          category,
        },
        35000,
      );
      await current(c);
      if (api.tabs?.sendMessage)
        await api.tabs
          .sendMessage(c.tabId, {
            type: "locklark:fill-fields",
            fields: response.fields,
          })
          .catch(() => {});
      status = "已请求填充所选条目；请核实网站结果";
    } catch {
      status = "此原生宿主暂不支持填充该条目类别";
    }
    updateBadge();
  }
  function candidateItems() {
    if (!context?.origin) return [];
    return rows
      .map((row) =>
        publicItem({
          ...row,
          category: "login",
          urls: [context.origin],
          state: "active",
        }),
      )
      .filter(Boolean);
  }
  async function vaultSearch(rawQuery, rawCategory) {
    if (!capability) throw Error("refused");
    const category = core.validCategory(rawCategory) ? rawCategory : "all";
    const query =
      typeof rawQuery === "string" ? rawQuery.slice(0, 500) : "";
    const canonical = core.normalizeCategory(category);
    try {
      const response = await request(
        "vault-search",
        {
          capability,
          query,
          category: canonical,
          favorites_only: category === "favorites",
        },
        12000,
      );
      const items = [];
      for (const item of response.items || []) {
        const publicEntry = publicItem(item);
        if (publicEntry) items.push(publicEntry);
      }
      vaultItems = items.slice(0, 500);
      status = `金库中有 ${vaultItems.length} 个条目`;
      return { items: vaultItems, source: "native", fallback: false };
    } catch {
      vaultItems = candidateItems();
      status = vaultItems.length
        ? "当前原生宿主仅提供当前网站候选"
        : "当前原生宿主不支持浏览完整金库";
      return {
        items: vaultItems,
        source: "candidates",
        fallback: true,
      };
    }
  }
  async function getVaultItem(itemId, revision) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(itemId || "") ||
      !/^[a-f0-9]{64}$/.test(revision || "")
    )
      throw Error("refused");
    const key = itemId + ":" + revision;
    try {
      const response = await request(
        "item-get",
        { capability, item_id: itemId, revision },
        12000,
      );
      const detail = publicDetail(response.item);
      if (!detail) throw Error("refused");
      detailCache.set(key, detail);
      return detail;
    } catch {
      const row = rows.find(
        (candidate) =>
          candidate.id === itemId && candidate.revision === revision,
      );
      if (!row) throw Error("refused");
      const detail = publicDetail({
        ...row,
        category: "login",
        urls: context?.origin ? [context.origin] : [],
        state: "active",
        fields: [],
      });
      if (!detail) throw Error("refused");
      detail.readOnly = true;
      detail.unavailable = "当前原生宿主不提供条目详情";
      detailCache.set(key, detail);
      return detail;
    }
  }
  async function saveVaultItem(message) {
    if (!capability || !core.validItemForSave(message.item))
      throw Error("refused");
    const mode = message.mode === "edit" ? "edit" : "create";
    if (
      mode === "edit" &&
      (!/^[a-f0-9]{32}$/.test(message.id || "") ||
        !/^[a-f0-9]{64}$/.test(message.revision || ""))
    )
      throw Error("refused");
    let itemJSON;
    try {
      itemJSON = JSON.stringify({
        ...message.item,
        category: core.normalizeCategory(message.item.category),
      });
    } catch {
      throw Error("refused");
    }
    if (
      typeof itemJSON !== "string" ||
      new TextEncoder().encode(itemJSON).length > 65536
    )
      throw Error("refused");
    let response;
    try {
      response = await request(
        "item-save",
        {
          capability,
          ...(mode === "edit"
            ? { item_id: message.id, revision: message.revision }
            : {}),
          item_json: itemJSON,
        },
        20000,
      );
    } catch {
      const error = Error("refused");
      error.keepStatus = true;
      status = "当前原生宿主不支持在扩展中保存条目";
      throw error;
    } finally {
      itemJSON = "";
    }
    if (
      !/^[a-f0-9]{32}$/.test(response.item_id || "") ||
      !/^[a-f0-9]{64}$/.test(response.revision || "")
    )
      throw Error("refused");
    status = "已保存";
    vaultItems = [];
    detailCache.clear();
    updateBadge();
    rebuildContextMenus();
    return { item_id: response.item_id, revision: response.revision };
  }
  async function setItemState(message) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    const state = ["active", "archived", "trashed"].includes(message.state)
      ? message.state
      : undefined;
    const favorite =
      typeof message.favorite === "boolean" ? message.favorite : undefined;
    if (!state && favorite === undefined) throw Error("refused");
    let response;
    try {
      response = await request(
        "item-state",
        {
          capability,
          item_id: message.id,
          revision: message.revision,
          ...(state ? { state } : {}),
          ...(favorite === undefined ? {} : { favorite }),
        },
        15000,
      );
    } catch {
      const error = Error("refused");
      error.keepStatus = true;
      status = "当前原生宿主不支持修改条目状态";
      throw error;
    }
    if (response.type !== "saved") throw Error("refused");
    status = state === "trashed" ? "条目已移至废纸篓" : "条目已更新";
    vaultItems = vaultItems.map((item) =>
      item.id === message.id
        ? {
            ...item,
            revision: response.revision,
            ...(state ? { state } : {}),
            ...(favorite === undefined ? {} : { favorite }),
          }
        : item,
    );
    const cached = detailCache.get(message.id + ":" + message.revision);
    if (cached)
      detailCache.set(message.id + ":" + response.revision, {
        ...cached,
        revision: response.revision,
        ...(state ? { state } : {}),
        ...(favorite === undefined ? {} : { favorite }),
      });
    updateBadge();
    rebuildContextMenus();
    return { revision: response.revision };
  }
  async function copyFieldValue(message) {
    const detail =
      detailCache.get(message.id + ":" + message.revision) ||
      (await getVaultItem(message.id, message.revision));
    const field = core
      .flattenItemFields(detail)
      .find((entry) => entry.id === message.field_id);
    if (!field) throw Error("refused");
    return {
      value: field.value,
      clearAfterSeconds: settings.clipboardClearSeconds,
    };
  }
  async function openAndFill(message) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    const target = message.url;
    const expectedOrigin = core.originFromURL(target);
    let urls = Array.isArray(message.urls)
      ? message.urls
          .slice(0, 20)
          .filter((url) => typeof url === "string")
      : [];
    if (!urls.length) {
      const detail = await getVaultItem(message.id, message.revision);
      urls = detail.urls;
    }
    if (!core.itemURLAllowed({ urls }, target)) throw Error("refused");
    if (typeof api.tabs?.create !== "function") throw Error("refused");
    const created = await api.tabs.create({ url: target, active: true });
    if (!created || !Number.isSafeInteger(created.id) || created.id < 1)
      throw Error("refused");
    clearPendingOpenAndFill();
    pendingOpenAndFill = {
      tabId: created.id,
      expectedOrigin,
      itemId: message.id,
      revision: message.revision,
      expiresAt: Date.now() + 15000,
    };
    openAndFillTimer = setTimeout(() => {
      if (!pendingOpenAndFill) return;
      pendingOpenAndFill = null;
      openAndFillTimer = null;
      status = "打开并填充已超时；未执行填充";
      updateBadge();
    }, 15000);
    status = "已打开页面，等待加载后填充";
    return { tabId: created.id, origin: expectedOrigin };
  }
  async function processOpenAndFill(tabId, change) {
    const pendingFill = pendingOpenAndFill;
    if (!pendingFill || pendingFill.tabId !== tabId) return;
    if (typeof change?.url === "string") {
      let changedOrigin = "";
      try {
        changedOrigin = core.originFromURL(change.url);
      } catch {}
      if (changedOrigin && changedOrigin !== pendingFill.expectedOrigin) {
        clearPendingOpenAndFill();
        status = "打开并填充已取消：页面跳转到其他来源";
        updateBadge();
        return;
      }
    }
    if (change?.status !== "complete") return;
    if (Date.now() > pendingFill.expiresAt) {
      clearPendingOpenAndFill();
      status = "打开并填充已超时；未执行填充";
      updateBadge();
      return;
    }
    clearPendingOpenAndFill();
    try {
      const tabs = await api.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (
        tabs.length !== 1 ||
        tabs[0].id !== tabId ||
        core.originFromURL(tabs[0].url) !== pendingFill.expectedOrigin
      )
        throw Error("refused");
      await match();
      const row = rows.find(
        (candidate) =>
          candidate.id === pendingFill.itemId &&
          candidate.revision === pendingFill.revision,
      );
      if (!row) throw Error("refused");
      await fill(row.id, row.revision);
    } catch {
      status = "打开并填充未完成；请重新读取当前网站候选";
      updateBadge();
    }
  }
  function contentSender(sender) {
    try {
      return (
        sender?.id === api.runtime.id &&
        sender.frameId === 0 &&
        Number.isSafeInteger(sender.tab?.id) &&
        typeof sender.documentId === "string" &&
        sender.documentId.length > 0 &&
        core.originFromURL(sender.url) === core.originFromURL(sender.tab.url)
      );
    } catch {
      return false;
    }
  }
  async function contentContext(sender) {
    const c = await capture();
    if (
      c.tabId !== sender.tab.id ||
      c.windowId !== sender.tab.windowId ||
      c.documentId !== sender.documentId ||
      c.origin !== core.originFromURL(sender.url)
    )
      throw Error("refused");
    return c;
  }
  async function fromContent(message, sender) {
    if (!message || typeof message !== "object") throw Error("refused");
    // Cancellation authenticates the original document even after navigation.
    if (message.type === "passkey-cancel") {
      if (
        pendingPasskey?.pageID === message.id &&
        pendingPasskey.tabId === sender.tab.id &&
        pendingPasskey.documentId === sender.documentId
      )
        cancelContext();
      return {};
    }
    const c = await contentContext(sender);
    await settingsReady;
    if (message.type === "inline-state")
      return { connected: !!capability, offerSavePasskeys, offerUsePasskeys };
    if (message.type === "inline-connect") {
      if (!capability) await connect();
      await current(c);
      return { connected: !!capability };
    }
    if (message.type === "inline-match") {
      if (!capability || pending || pendingOTP || pendingPasskey)
        return { connected: !!capability, candidates: [] };
      if (!core.sameContext(c, context) || Date.now() - lastMatchAt > 3000) {
        await match();
        lastMatchAt = Date.now();
      }
      await current(c);
      return {
        connected: !!capability,
        candidates: rows.map((r) => ({
          id: r.id,
          revision: r.revision,
          title: r.title,
        })),
      };
    }
    if (
      ["inline-fill", "inline-save", "inline-update", "inline-otp"].includes(
        message.type,
      )
    ) {
      if (!core.sameContext(context, c)) throw Error("refused");
      if (message.type === "inline-fill")
        await fill(message.id, message.revision);
      else if (message.type === "inline-otp")
        await otp(message.id, message.revision);
      else if (message.type === "inline-update")
        await save(message.id, message.revision);
      else await save();
      return { status };
    }
    if (
      message.type !== "passkey" ||
      !["create", "get"].includes(message.operation) ||
      !/^[a-f0-9-]{36}$/.test(message.id || "") ||
      typeof message.options !== "string" ||
      message.options.length > 32768 ||
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    if (message.operation === "create" ? !offerSavePasskeys : !offerUsePasskeys)
      throw Error("refused");
    const generation = epoch,
      intent = {
        ...c,
        pageID: message.id,
        create: message.operation === "create",
      };
    pendingPasskey = intent;
    status = "请在原生窗口确认 Passkey 操作";
    try {
      const result = await request(
        "passkey-" + message.operation,
        { ...fields(c), options: message.options },
        125000,
      );
      await current(c);
      if (generation !== epoch || pendingPasskey !== intent)
        throw Error("refused");
      const credential = JSON.parse(result.credential);
      if (intent.create) passkeyUnknown = false;
      status = "Passkey 已交付；请核实网站结果";
      return { credential };
    } catch (error) {
      if (intent.create && !error.knownRefusal) {
        passkeyUnknown = true;
        error.passkeyUnknown = true;
      }
      throw error;
    } finally {
      if (pendingPasskey === intent) {
        pendingPasskey = null;
        context = null;
        rows = [];
      }
    }
  }
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (!contentSender(sender)) return false;
    fromContent(message, sender).then(respond, (error) =>
      respond(
        error.passkeyUnknown
          ? { error: "NotAllowedError" }
          : { fallback: true },
      ),
    );
    return true;
  });
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!core.validSender(sender, api.runtime)) return false;
    const requestEpoch = epoch;
    const run = async () => {
      if (!message || typeof message !== "object") throw Error("refused");
      const extra = {};
      switch (message.type) {
        case "state":
          await settingsReady;
          break;
        case "settings": {
          await settingsReady;
          const next = {
            ...settings,
            generatorDefaults: { ...settings.generatorDefaults },
            loginOverrides: { ...settings.loginOverrides },
            disabledInlineMenuOrigins: [
              ...settings.disabledInlineMenuOrigins,
            ],
            neverSaveOrigins: [...settings.neverSaveOrigins],
          };
          for (const key of [
            "autoLogin",
            "offerSavePasskeys",
            "offerUsePasskeys",
            "sharedDesktopSession",
            "allowBiometricUnlock",
            "showToolbarBadgeCount",
            "showInlineMenu",
            "openAndFillAutoSubmit",
            "offerFillIdentitiesAndCards",
            "offerSaveLogins",
            "showInlineGenerator",
            "watchtowerLocalChecks",
          ])
            if (typeof message[key] === "boolean") next[key] = message[key];
          if (
            /^[a-f0-9]{32}$/.test(message.id || "") &&
            typeof message.enabled === "boolean"
          )
            next.loginOverrides[message.id] = message.enabled;
          if (["system", "light", "dark"].includes(message.theme))
            next.theme = message.theme;
          if (
            Number.isSafeInteger(message.clipboardClearSeconds) &&
            message.clipboardClearSeconds >= 5 &&
            message.clipboardClearSeconds <= 300
          )
            next.clipboardClearSeconds = message.clipboardClearSeconds;
          const normalized = core.normalizeSettings(next);
          await api.storage.local.set(normalized);
          applySettings(normalized);
          updateBadge();
          rebuildContextMenus();
          break;
        }
        case "connect":
          void connect();
          break;
        case "disconnect":
          disconnectWithStatus("已断开");
          break;
        case "lock":
          lockVault();
          break;
        case "match":
          await match();
          break;
        case "save-new":
          void save().catch(() => {
            if (requestEpoch === epoch)
              status = unconfirmedSave ? SAVE_UNKNOWN : "未保存";
          });
          break;
        case "save-update":
          if (
            typeof message.id !== "string" ||
            typeof message.revision !== "string"
          )
            throw Error("refused");
          void save(message.id, message.revision).catch(() => {
            if (requestEpoch === epoch)
              status = unconfirmedSave ? SAVE_UNKNOWN : "未保存";
          });
          break;
        case "otp":
          if (
            Object.keys(message).sort().join(",") !== "id,revision,type" ||
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "")
          )
            throw Error("refused");
          void otp(message.id, message.revision).catch(() => {
            if (requestEpoch === epoch) status = "本次验证码填充被拒绝";
          });
          break;
        case "cancel-otp":
          if (Object.keys(message).join(",") !== "type") throw Error("refused");
          cancelOTP();
          break;
        case "fill":
          if (
            typeof message.id !== "string" ||
            typeof message.revision !== "string"
          )
            throw Error("refused");
          void fill(message.id, message.revision).catch(() => {
            if (requestEpoch === epoch) status = "本次请求被拒绝";
          });
          break;
        case "vault-search":
        case "vault-list": {
          await settingsReady;
          const result = await vaultSearch(message.query, message.category);
          extra.vaultItems = result.items;
          extra.vaultSource = result.source;
          extra.vaultFallback = result.fallback;
          break;
        }
        case "item-get":
          if (
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "")
          )
            throw Error("refused");
          extra.detail = await getVaultItem(message.id, message.revision);
          break;
        case "item-save": {
          await settingsReady;
          const saved = await saveVaultItem(message);
          extra.saved = saved;
          break;
        }
        case "item-state":
          extra.itemState = await setItemState(message);
          break;
        case "copy-field":
          if (
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "") ||
            typeof message.field_id !== "string" ||
            message.field_id.length > 128
          )
            throw Error("refused");
          extra.copiedField = await copyFieldValue(message);
          break;
        case "open-and-fill":
          extra.openAndFill = await openAndFill(message);
          break;
        case "generate":
          extra.generatedPassword = await generatePasswordValue(
            message.options,
          );
          break;
        case "site-settings":
          await setSiteSettings(
            typeof message.disabledInline === "boolean"
              ? message.disabledInline
              : typeof message.disabledInlineMenu === "boolean"
                ? message.disabledInlineMenu
                : undefined,
            typeof message.neverSave === "boolean"
              ? message.neverSave
              : undefined,
          );
          break;
        default:
          throw Error("refused");
      }
      return { ...snapshot(), ...extra };
    };
    run().then(sendResponse, (error) => {
      if (requestEpoch === epoch && !error?.keepStatus)
        status = unconfirmedSave
          ? SAVE_UNKNOWN
          : "操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面";
      sendResponse({
        ...snapshot(),
        candidates: [],
        origin: "",
        ...(error?.keepStatus ? {} : { vaultItems: [] }),
      });
    });
    return true;
  });
})();
