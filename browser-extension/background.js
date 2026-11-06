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
    autoLogin = false,
    offerSavePasskeys = true,
    offerUsePasskeys = true,
    offerSaveLogins = true,
    neverSaveOrigins = [],
    loginOverrides = {},
    generatorDefaults = {
      mode: "random",
      length: 24,
      digits: true,
      symbols: true,
      wordCount: 4,
      separator: "hyphens",
      capitalize: true,
      pinLength: 6,
    },
    lastMatchAt = 0,
    hostCapabilities = [];
  const STAGED_TTL = 5 * 60 * 1000,
    LAST_FILLED_TTL = 60 * 1000,
    HISTORY_LIMIT = 20;
  const stagedSaves = new Map(),
    lastFilledCredentials = new Map(),
    generatedHistory = [];
  const settingsReady =
    api.storage?.local
      .get([
        "autoLogin",
        "loginOverrides",
        "offerSavePasskeys",
        "offerUsePasskeys",
        "offerSaveLogins",
        "neverSaveOrigins",
        "generatorDefaults",
      ])
      .then((value) => {
        autoLogin = value.autoLogin !== false;
        offerSavePasskeys = value.offerSavePasskeys !== false;
        offerUsePasskeys = value.offerUsePasskeys !== false;
        offerSaveLogins = value.offerSaveLogins !== false;
        neverSaveOrigins = sanitizeOrigins(value.neverSaveOrigins);
        generatorDefaults = sanitizeGeneratorDefaults(value.generatorDefaults);
        loginOverrides =
          value.loginOverrides && typeof value.loginOverrides === "object"
            ? value.loginOverrides
            : {};
      })
      .catch(() => {}) || Promise.resolve();
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
  function sanitizeOrigins(value) {
    if (!Array.isArray(value)) return [];
    const out = [];
    for (const origin of value.slice(0, 256)) {
      try {
        if (typeof origin === "string" && core.originFromURL(origin) === origin)
          if (!out.includes(origin)) out.push(origin);
      } catch {}
    }
    return out;
  }
  function sanitizeGeneratorDefaults(value) {
    const source = value && typeof value === "object" ? value : {};
    return {
      mode: ["random", "memorable", "pin"].includes(source.mode)
        ? source.mode
        : "random",
      length: Number.isSafeInteger(source.length) ? source.length : 24,
      digits: source.digits !== false,
      symbols: source.symbols !== false,
      wordCount: Number.isSafeInteger(source.wordCount) ? source.wordCount : 4,
      separator: typeof source.separator === "string" ? source.separator : "hyphens",
      capitalize: source.capitalize !== false,
      pinLength: Number.isSafeInteger(source.pinLength) ? source.pinLength : 6,
    };
  }
  function validCredentialText(value, allowEmpty = false) {
    return (
      typeof value === "string" &&
      (allowEmpty || value.length > 0) &&
      value.length <= 16384 &&
      value.isWellFormed()
    );
  }
  function zeroStaged(record) {
    if (!record) return;
    if (record.timer) clearTimeout(record.timer);
    record.timer = null;
    record.password = "";
  }
  function removeStaged(stageId) {
    const record = stagedSaves.get(stageId);
    if (!record) return null;
    zeroStaged(record);
    stagedSaves.delete(stageId);
    return record;
  }
  function clearStaged() {
    for (const record of stagedSaves.values()) zeroStaged(record);
    stagedSaves.clear();
  }
  function clearGeneratedHistory() {
    for (const entry of generatedHistory) entry.password = "";
    generatedHistory.length = 0;
  }
  function clearLastFilled() {
    for (const entry of lastFilledCredentials.values()) entry.password = "";
    lastFilledCredentials.clear();
  }
  function clearPrivateSessions() {
    clearStaged();
    clearGeneratedHistory();
    clearLastFilled();
  }
  function pruneStaged() {
    const now = Date.now();
    for (const [stageId, record] of stagedSaves)
      if (!(now < record.expiresAt)) removeStaged(stageId);
    for (const [tabId, entry] of lastFilledCredentials)
      if (!(now < entry.expiresAt)) {
        entry.password = "";
        lastFilledCredentials.delete(tabId);
      }
  }
  function stagedForTab(tabId, origin) {
    pruneStaged();
    for (const record of stagedSaves.values())
      if (
        record.tabId === tabId &&
        record.origin === origin &&
        (record.mode === "new" || record.mode === "update")
      )
        return record;
    return null;
  }
  function serializeStaged(record) {
    if (!record) return null;
    return {
      stageId: record.stageId,
      origin: record.origin,
      username: record.username,
      title: record.title,
      mode: record.mode,
      existingItemId: record.existingItemId,
      existingRevision: record.existingRevision,
      expiresAt: record.expiresAt,
      connected: !!capability,
      candidates: rows
        .filter((row) => row.state === "active")
        .map((row) => ({ id: row.id, revision: row.revision, title: row.title })),
    };
  }
  function armStagedTimer(record) {
    record.timer = setTimeout(() => {
      if (stagedSaves.get(record.stageId) === record) removeStaged(record.stageId);
    }, Math.max(1, record.expiresAt - Date.now()));
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
    hostCapabilities = [];
    advanceEpoch();
    for (const [requestId, c] of calls) {
      retired.add(requestId);
      clearTimeout(c.timer);
      c.reject(Error("refused"));
    }
    calls.clear();
  }
  function disconnect(preservePrivateSessions = false) {
    const p = port;
    port = null;
    clear();
    if (!preservePrivateSessions) clearPrivateSessions();
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
    disconnect(true);
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
      clearPrivateSessions();
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
        clearPrivateSessions();
        status = uncertain
          ? "原生金库已锁定 · 结果未确认，请在金库核实，勿重复保存"
          : "原生金库已锁定，请重新连接并配对";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        return;
      }
      if (message.type === "unpaired") {
        const uncertain = unconfirmedSave;
        clear();
        clearPrivateSessions();
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
        "stage-save": "save-staged",
        "pending-save": "save-pending",
        "commit-staged-save": "saved",
        "dismiss-save": "save-dismissed",
        generate: "generated",
        otp: "otp-ready",
        "otp-ack": "otp-fill",
        "cancel-otp": "cancelled",
        "passkey-create": "passkey-result",
        "passkey-get": "passkey-result",
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
      hostCapabilities = Array.isArray(response.capabilities)
        ? response.capabilities.filter(
            (value) => typeof value === "string" && value.length <= 64,
          )
        : [];
      status = "已连接，请读取当前网站候选";
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
      // Remember the exact credential that was just injected so an unchanged
      // sign-in does not trigger a save prompt after submission.
      const previousFill = lastFilledCredentials.get(c.tabId);
      if (previousFill) previousFill.password = "";
      lastFilledCredentials.set(c.tabId, {
        origin: c.origin,
        itemId,
        revision,
        username: response.username,
        password: response.password,
        filledAt: Date.now(),
        expiresAt: Date.now() + LAST_FILLED_TTL,
      });
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
    }
  }
  function generatorOptions(params = {}) {
    const mode = ["random", "memorable", "pin"].includes(params.mode)
      ? params.mode
      : "random";
    if (mode === "memorable") {
      const length =
        Number.isSafeInteger(params.length)
          ? params.length
          : params.wordCount ?? generatorDefaults.wordCount;
      return {
        mode,
        length,
        digits: typeof params.digits === "boolean" ? params.digits : false,
        separator:
          typeof params.separator === "string"
            ? params.separator
            : generatorDefaults.separator,
        capitalize:
          typeof params.capitalize === "boolean"
            ? params.capitalize
            : generatorDefaults.capitalize,
      };
    }
    if (mode === "pin")
      return {
        mode,
        length: Number.isSafeInteger(params.length)
          ? params.length
          : params.pinLength ?? generatorDefaults.pinLength,
      };
    return {
      mode,
      length: Number.isSafeInteger(params.length)
        ? params.length
        : generatorDefaults.length,
      digits:
        typeof params.digits === "boolean"
          ? params.digits
          : generatorDefaults.digits,
      symbols:
        typeof params.symbols === "boolean"
          ? params.symbols
          : generatorDefaults.symbols,
    };
  }
  async function generateResult(params) {
    const options = generatorOptions(params);
    if (capability && hostCapabilities.includes("generate-v1")) {
      try {
        const response = await request("generate", {
          capability,
          options: JSON.stringify(options),
        });
        if (
          response.type === "generated" &&
          typeof response.generated_password === "string"
        )
          return {
            password: response.generated_password,
            profile: response.profile,
            historyId: response.history_id || "",
          };
      } catch {}
    }
    return { ...core.generatePassword(options), historyId: "" };
  }
  function recordGenerated(origin, username, generated) {
    const entry = {
      id: id(),
      origin,
      username: typeof username === "string" ? username : "",
      password: generated.password,
      profile: generated.profile,
      createdAt: Date.now(),
    };
    generatedHistory.unshift(entry);
    while (generatedHistory.length > HISTORY_LIMIT) {
      const removed = generatedHistory.pop();
      if (removed) removed.password = "";
    }
    return entry.id;
  }
  function generatedHistoryView() {
    return generatedHistory.map((entry) => ({
      id: entry.id,
      origin: entry.origin,
      username: entry.username,
      password: entry.password,
      profile: entry.profile,
      createdAt: entry.createdAt,
    }));
  }
  function addNeverOrigin(origin) {
    if (neverSaveOrigins.includes(origin)) return;
    if (neverSaveOrigins.length >= 256) neverSaveOrigins.shift();
    neverSaveOrigins.push(origin);
  }
  async function persistNeverOrigins() {
    try {
      await api.storage.local.set({ neverSaveOrigins: [...neverSaveOrigins] });
    } catch {}
  }
  async function stageSave(values, c) {
    pruneStaged();
    if (!validCredentialText(values?.password)) return { mode: "never" };
    const username =
      typeof values.username === "string" ? values.username.slice(0, 16384) : "";
    if (!validCredentialText(username, true)) return { mode: "never" };
    if (!offerSaveLogins || neverSaveOrigins.includes(c.origin))
      return { mode: "never" };
    const last = lastFilledCredentials.get(c.tabId);
    if (
      last &&
      Date.now() < last.expiresAt &&
      last.origin === c.origin &&
      last.username === username &&
      last.password === values.password &&
      values.isPasswordChange !== true
    )
      return { mode: "unchanged" };
    // Only one pending save is kept per tab and origin. A new submission replaces
    // the previous proposal instead of leaking the older password for five minutes.
    for (const [stageId, record] of stagedSaves)
      if (record.tabId === c.tabId && record.origin === c.origin)
        removeStaged(stageId);
    let mode = values.isPasswordChange === true ? "update" : "new";
    let matched = null;
    if (capability) {
      if (
        (!context || context.origin !== c.origin || !rows.length) &&
        !pending &&
        !pendingOTP &&
        !pendingPasskey
      ) {
        try {
          await match();
        } catch {}
      }
      if (values.isPasswordChange === true && rows.length >= 1)
        matched = rows[0];
      else if (
        username &&
        rows.find(
          (row) =>
            row.title &&
            row.title.toLowerCase() === username.toLowerCase(),
        )
      )
        matched =
          rows.find(
            (row) =>
              row.title &&
              row.title.toLowerCase() === username.toLowerCase(),
          ) || null;
      else if (
        typeof values.itemId === "string" &&
        rows.some(
          (row) =>
            row.id === values.itemId && row.revision === values.revision,
        )
      )
        matched =
          rows.find((row) => row.id === values.itemId) || null;
      if (matched) mode = "update";
    }
    const title =
      typeof values.title === "string" && values.title.trim()
        ? values.title.trim().slice(0, 1024)
        : new URL(c.origin).hostname;
    const record = {
      stageId: id(),
      tabId: c.tabId,
      windowId: c.windowId,
      origin: c.origin,
      username,
      password: values.password,
      title,
      isNewPassword: values.isNewPassword === true,
      isPasswordChange: values.isPasswordChange === true,
      mode,
      existingItemId: matched?.id || "",
      existingRevision: matched?.revision || "",
      createdAt: Date.now(),
      expiresAt: Date.now() + STAGED_TTL,
      native: false,
      timer: null,
    };
    if (capability && hostCapabilities.includes("stage-save-v1")) {
      try {
        const response = await request("stage-save", {
          capability,
          origin: c.origin,
          tab_id: c.tabId,
          document_id: c.documentId,
          window_id: c.windowId,
          username,
          password: values.password,
          mode,
          title,
          item_id: record.existingItemId,
          revision: record.existingRevision,
        });
        const staged = response.staged_save;
        if (staged) {
          record.stageId = staged.stage_id;
          record.origin = staged.origin;
          record.username = staged.username;
          record.title = staged.title;
          record.mode = staged.mode;
          record.existingItemId = staged.existing_item_id || "";
          record.existingRevision = staged.existing_revision || "";
          if (Number.isSafeInteger(staged.expires_at))
            record.expiresAt = Math.min(record.expiresAt, staged.expires_at);
          record.native = true;
        }
      } catch {
        record.native = false;
      }
    }
    if (record.mode === "unchanged" || record.mode === "never")
      return { mode: record.mode };
    stagedSaves.set(record.stageId, record);
    armStagedTimer(record);
    return { mode: record.mode, stageId: record.stageId };
  }
  async function commitStagedSave(stageId, options, c) {
    pruneStaged();
    const record = stagedSaves.get(stageId);
    if (
      !record ||
      record.origin !== c.origin ||
      !(Date.now() < record.expiresAt) ||
      record.committing
    )
      throw Error("refused");
    record.committing = true;
    // connect() advances the epoch, so only capture the generation after a
    // possible lazy connection. The staged record itself survives the clear.
    if (!capability) await connect();
    const generation = epoch;
    try {
      await settingsReady;
      if (!capability || generation !== epoch) throw Error("refused");
      await current(c);
      let mode = ["new", "update"].includes(options?.mode)
        ? options.mode
        : record.mode;
      let itemId =
        typeof options?.itemId === "string"
          ? options.itemId
          : record.existingItemId;
      let revision =
        typeof options?.revision === "string"
          ? options.revision
          : record.existingRevision;
      if (!context || context.origin !== c.origin || !rows.length) {
        try {
          await match();
        } catch {}
      }
      if (mode === "update") {
        const matchRow = () =>
          rows.find((row) => row.id === itemId) ||
          rows.find((row) => row.title === record.title) ||
          (rows.length === 1 ? rows[0] : null);
        if (!itemId || !revision || !rows.some((row) => row.id === itemId)) {
          const found = matchRow();
          if (found) {
            itemId = found.id;
            revision = found.revision;
          } else mode = "new";
        }
      }
      if (mode === "update" && (!itemId || !revision)) mode = "new";
      const title =
        typeof options?.title === "string" && options.title.trim()
          ? options.title.trim().slice(0, 1024)
          : record.title;
      let result;
      if (hostCapabilities.includes("stage-save-v1")) {
        result = await request("commit-staged-save", {
          capability,
          stage_id: stageId,
          origin: c.origin,
          tab_id: c.tabId,
          document_id: c.documentId,
          window_id: c.windowId,
          title,
          mode,
          item_id: mode === "update" ? itemId : "",
          revision: mode === "update" ? revision : "",
        });
        if (result.type !== "saved") throw Error("refused");
      } else {
        await verifySaveDocument(c, generation);
        const fieldsToSend = {
          ...fields(c),
          window_id: c.windowId,
          username: record.username,
          password: record.password,
        };
        if (mode === "update") {
          fieldsToSend.item_id = itemId;
          fieldsToSend.revision = revision;
        } else {
          // A v1 save-update must not carry a title (the native host binds it to
          // the existing row); save-new may use the user-edited title.
          fieldsToSend.title = title;
        }
        const ready = await request(
          mode === "update" ? "save-update" : "save-new",
          fieldsToSend,
          35000,
        );
        if (ready.type !== "save-ready") throw Error("refused");
        await verifySaveDocument(c, generation);
        if (generation !== epoch) throw Error("refused");
        record.commitStarted = true;
        unconfirmedSave = true;
        result = await request("commit-ready", {
          capability,
          request_id: ready.id,
          nonce: ready.nonce,
        });
        if (result.type === "saved") unconfirmedSave = false;
        if (result.type !== "saved") throw Error("refused");
      }
      removeStaged(stageId);
      status = "已保存";
      return { saved: true, mode, title, status };
    } catch (error) {
      if (!record.commitStarted || !unconfirmedSave) status = "未保存";
      throw error;
    } finally {
      record.committing = false;
    }
  }
  async function dismissStaged(stageId, neverForOrigin, c, originOverride) {
    pruneStaged();
    const record = stageId ? stagedSaves.get(stageId) : null;
    const origin = record?.origin || originOverride || c?.origin || "";
    if (neverForOrigin) {
      try {
        if (core.originFromURL(origin) === origin) {
          addNeverOrigin(origin);
          await persistNeverOrigins();
        }
      } catch {}
    }
    if (
      record &&
      capability &&
      hostCapabilities.includes("stage-save-v1") &&
      record.native
    ) {
      try {
        const response = await request("dismiss-save", {
          capability,
          stage_id: record.stageId,
          never_for_origin: neverForOrigin === true,
        });
        if (Array.isArray(response.never_origins))
          neverSaveOrigins = sanitizeOrigins(response.never_origins);
      } catch {}
    }
    if (record) removeStaged(record.stageId);
    return {
      dismissed: true,
      neverSaveOrigins: [...neverSaveOrigins],
      pendingSave: serializeStaged(stagedForTab(c?.tabId, c?.origin)),
    };
  }
  async function inlineGenerateFill(params, c, generation) {
    const suppliedPassword =
      typeof params?.password === "string" &&
      params.password.length >= 4 &&
      params.password.length <= 256 &&
      params.password.isWellFormed()
        ? params.password
        : "";
    let generated;
    if (suppliedPassword) {
      let profile = null;
      if (
        params.profile &&
        typeof params.profile === "object" &&
        !Array.isArray(params.profile) &&
        ["random", "memorable", "pin"].includes(params.profile.mode) &&
        Number.isSafeInteger(params.profile.length) &&
        params.profile.length >= 1 &&
        params.profile.length <= 256 &&
        Number.isSafeInteger(params.profile.alphabet_size) &&
        params.profile.alphabet_size >= 2 &&
        params.profile.alphabet_size <= 1000000 &&
        Number.isSafeInteger(params.profile.entropy_bits_floor) &&
        params.profile.entropy_bits_floor >= 0
      )
        profile = {
          mode: params.profile.mode,
          length: params.profile.length,
          alphabet_size: params.profile.alphabet_size,
          entropy_bits_floor: params.profile.entropy_bits_floor,
        };
      if (!profile)
        profile = core.generatePassword(generatorOptions(params)).profile;
      generated = {
        password: suppliedPassword,
        profile,
        historyId: "",
      };
    } else generated = await generateResult(params);
    const historyId = recordGenerated(
      c.origin,
      typeof params.username === "string" ? params.username : "",
      generated,
    );
    let fill = null;
    try {
      const results = await api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.fillGeneratedPassword,
        args: [c.origin, generated.password, Date.now() + 1500],
      });
      if (
        generation === epoch &&
        results.length === 1 &&
        results[0].frameId === 0 &&
        results[0].documentId === c.documentId &&
        results[0].result?.ok === true
      )
        fill = results[0].result;
    } catch {}
    const staged = await stageSave(
      {
        username: fill?.username || params.username || "",
        password: generated.password,
        isNewPassword: true,
        isPasswordChange: fill?.isPasswordChange === true,
      },
      c,
    );
    return {
      password: generated.password,
      profile: generated.profile,
      historyId,
      filledCount: fill?.filledCount || 0,
      stageId: staged.stageId || "",
      mode: staged.mode || "",
    };
  }
  async function activeTabInfo() {
    try {
      const tabs = await api.tabs.query({ active: true, currentWindow: true });
      if (tabs.length !== 1) return null;
      const tab = tabs[0];
      if (!Number.isSafeInteger(tab.id) || !Number.isSafeInteger(tab.windowId))
        return null;
      return {
        tabId: tab.id,
        windowId: tab.windowId,
        origin: core.originFromURL(tab.url),
      };
    } catch {
      return null;
    }
  }
  async function activePendingSave() {
    const info = await activeTabInfo();
    return info ? serializeStaged(stagedForTab(info.tabId, info.origin)) : null;
  }
  function statePayload(extra = {}) {
    return {
      connected: !!capability,
      autoLogin,
      quickFill,
      loginOverrides,
      offerSavePasskeys,
      offerUsePasskeys,
      offerSaveLogins,
      neverSaveOrigins: [...neverSaveOrigins],
      generatorDefaults: { ...generatorDefaults },
      generatedHistory: generatedHistoryView(),
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
      pending: !!pending || !!pendingOTP || !!pendingPasskey,
      otpPending: !!pendingOTP,
      saveBlocked: unconfirmedSave,
      origin: context?.origin || "",
      ...extra,
    };
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
      return;
    }
    if (pending?.injectionStarted) fillUnknown = true;
    if (pendingOTP) {
      cancelOTP();
      return;
    }
    if (!context && !pending) return;
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
  }
  api.tabs.onActivated.addListener(cancelContext);
  api.tabs.onUpdated.addListener((tabId, change) => {
    if (
      (context?.tabId === tabId ||
        pending?.tabId === tabId ||
        pendingOTP?.tabId === tabId ||
        pendingPasskey?.tabId === tabId) &&
      ("url" in change || change.status === "loading")
    )
      cancelContext();
  });
  api.windows.onFocusChanged.addListener((windowId) => {
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
      return {
        connected: !!capability,
        offerSavePasskeys,
        offerUsePasskeys,
        offerSaveLogins,
        neverSaveForOrigin: neverSaveOrigins.includes(c.origin),
        suppressInline: neverSaveOrigins.includes(c.origin),
        generatorDefaults: { ...generatorDefaults },
      };
    if (message.type === "inline-connect") {
      if (!capability) await connect();
      await current(c);
      return { connected: !!capability };
    }
    if (message.type === "inline-pending-save")
      return { pendingSave: serializeStaged(stagedForTab(c.tabId, c.origin)) };
    if (message.type === "inline-stage-save") {
      if (
        !validCredentialText(message.password) ||
        (message.username !== undefined &&
          !validCredentialText(message.username, true))
      )
        throw Error("refused");
      const staged = await stageSave(
        {
          username: message.username || "",
          password: message.password,
          isNewPassword: message.isNewPassword === true,
          isPasswordChange: message.isPasswordChange === true,
          title: message.title,
          itemId: message.itemId,
          revision: message.revision,
        },
        c,
      );
      return {
        ...staged,
        pendingSave:
          staged.mode === "new" || staged.mode === "update"
            ? serializeStaged(stagedForTab(c.tabId, c.origin))
            : null,
      };
    }
    if (message.type === "inline-commit-staged-save") {
      if (typeof message.stageId !== "string" || !/^[a-f0-9]{32}$/.test(message.stageId))
        throw Error("refused");
      const result = await commitStagedSave(
        message.stageId,
        {
          mode: message.mode,
          itemId: message.itemId,
          revision: message.revision,
          title: message.title,
        },
        c,
      );
      return { ...result, pendingSave: null, status };
    }
    if (message.type === "inline-dismiss-save") {
      const result = await dismissStaged(
        typeof message.stageId === "string" ? message.stageId : "",
        message.neverForOrigin === true,
        c,
      );
      return { ...result, status };
    }
    if (message.type === "inline-generate") {
      const generated = await generateResult(message);
      const historyId =
        message.recordHistory === true
          ? recordGenerated(
              c.origin,
              typeof message.username === "string" ? message.username : "",
              generated,
            )
          : generated.historyId || "";
      return {
        password: generated.password,
        profile: generated.profile,
        historyId,
      };
    }
    if (message.type === "inline-generate-fill") {
      const result = await inlineGenerateFill(message, c, epoch);
      return { ...result, status };
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
        neverSaveForOrigin: neverSaveOrigins.includes(c.origin),
        suppressInline: neverSaveOrigins.includes(c.origin),
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
      switch (message.type) {
        case "state":
          await settingsReady;
          break;
        case "settings": {
          await settingsReady;
          const next = {
            autoLogin,
            offerSavePasskeys,
            offerUsePasskeys,
            offerSaveLogins,
            neverSaveOrigins: [...neverSaveOrigins],
            generatorDefaults: { ...generatorDefaults },
            loginOverrides: { ...loginOverrides },
          };
          for (const key of [
            "autoLogin",
            "offerSavePasskeys",
            "offerUsePasskeys",
            "offerSaveLogins",
          ])
            if (typeof message[key] === "boolean") next[key] = message[key];
          if (
            message.generatorDefaults &&
            typeof message.generatorDefaults === "object" &&
            !Array.isArray(message.generatorDefaults)
          )
            next.generatorDefaults = sanitizeGeneratorDefaults(
              message.generatorDefaults,
            );
          if (
            /^[a-f0-9]{32}$/.test(message.id || "") &&
            typeof message.enabled === "boolean"
          )
            next.loginOverrides[message.id] = message.enabled;
          await api.storage.local.set(next);
          ({
            autoLogin,
            offerSavePasskeys,
            offerUsePasskeys,
            offerSaveLogins,
            neverSaveOrigins,
            generatorDefaults,
            loginOverrides,
          } = next);
          break;
        }
        case "clear-never-save-origin": {
          const info = await activeTabInfo();
          if (!info) throw Error("refused");
          neverSaveOrigins = neverSaveOrigins.filter(
            (origin) => origin !== info.origin,
          );
          await persistNeverOrigins();
          break;
        }
        case "connect":
          void connect();
          break;
        case "disconnect":
          disconnectWithStatus("已断开");
          break;
        case "match":
          await match();
          break;
        case "commit-staged-save": {
          if (!/^[a-f0-9]{32}$/.test(message.stageId || ""))
            throw Error("refused");
          const c = await capture();
          const result = await commitStagedSave(
            message.stageId,
            {
              mode: message.mode,
              itemId: message.itemId,
              revision: message.revision,
              title: message.title,
            },
            c,
          );
          return { ...result };
        }
        case "dismiss-staged-save":
        case "never-save-origin": {
          const c = await capture();
          const stageId = /^[a-f0-9]{32}$/.test(message.stageId || "")
            ? message.stageId
            : "";
          const result = await dismissStaged(
            stageId,
            message.type === "never-save-origin" ||
              message.neverForOrigin === true,
            c,
          );
          return { ...result, status };
        }
        case "generate":
        case "popup-generate": {
          const generated = await generateResult(message);
          let historyId = generated.historyId || "";
          if (message.recordHistory === true) {
            const info = await activeTabInfo();
            historyId = recordGenerated(
              info?.origin || "",
              typeof message.username === "string" ? message.username : "",
              generated,
            );
          }
          return {
            password: generated.password,
            profile: generated.profile,
            historyId,
          };
        }
        case "generator-fill": {
          const c = await capture();
          const result = await inlineGenerateFill(message, c, epoch);
          return { ...result, status };
        }
        case "generator-history-fill": {
          if (!/^[a-f0-9]{32}$/.test(message.historyId || ""))
            throw Error("refused");
          const c = await capture();
          const entry = generatedHistory.find(
            (item) => item.id === message.historyId,
          );
          if (
            !entry ||
            entry.origin !== c.origin ||
            typeof entry.password !== "string" ||
            entry.password.length < 4 ||
            entry.password.length > 256 ||
            !entry.password.isWellFormed()
          )
            throw Error("refused");
          let fill = null;
          try {
            const results = await api.scripting.executeScript({
              target: { tabId: c.tabId, documentIds: [c.documentId] },
              func: core.fillGeneratedPassword,
              args: [c.origin, entry.password, Date.now() + 1500],
            });
            if (
              results.length === 1 &&
              results[0].frameId === 0 &&
              results[0].documentId === c.documentId &&
              results[0].result?.ok === true
            )
              fill = results[0].result;
          } catch {}
          const staged = await stageSave(
            {
              username: fill?.username || entry.username || "",
              password: entry.password,
              isNewPassword: true,
              isPasswordChange: fill?.isPasswordChange === true,
            },
            c,
          );
          return {
            password: entry.password,
            profile: entry.profile,
            historyId: entry.id,
            filledCount: fill?.filledCount || 0,
            stageId: staged.stageId || "",
            mode: staged.mode || "",
            status,
          };
        }
        case "generator-history-save": {
          if (!/^[a-f0-9]{32}$/.test(message.historyId || ""))
            throw Error("refused");
          const c = await capture();
          const entry = generatedHistory.find(
            (item) => item.id === message.historyId,
          );
          if (
            !entry ||
            entry.origin !== c.origin ||
            typeof entry.password !== "string" ||
            entry.password.length < 4 ||
            entry.password.length > 256 ||
            !entry.password.isWellFormed()
          )
            throw Error("refused");
          const staged = await stageSave(
            {
              username: entry.username || "",
              password: entry.password,
              isNewPassword: true,
              isPasswordChange: false,
            },
            c,
          );
          return {
            password: entry.password,
            profile: entry.profile,
            historyId: entry.id,
            filledCount: 0,
            stageId: staged.stageId || "",
            mode: staged.mode || "",
            status: staged.stageId
              ? "已暂存生成密码，请确认保存"
              : status,
          };
        }
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
        default:
          throw Error("refused");
      }
      return {};
    };
    const respondState = async (extra = {}) => {
      let pendingSave = null;
      try {
        pendingSave = await activePendingSave();
      } catch {}
      sendResponse(statePayload({ ...extra, pendingSave }));
    };
    run().then(
      (extra) => respondState(extra),
      () => {
        if (requestEpoch === epoch)
          status = unconfirmedSave
            ? SAVE_UNKNOWN
            : "操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面";
        return respondState();
      },
    );
    return true;
  });
})();
