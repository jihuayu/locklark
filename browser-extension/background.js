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
    loginOverrides = {},
    lastMatchAt = 0,
    matchCategory = "login";
  const MULTI_STEP_TTL = 120000,
    multiStepSessions = new Map();
  const settingsReady =
    api.storage?.local
      .get([
        "autoLogin",
        "loginOverrides",
        "offerSavePasskeys",
        "offerUsePasskeys",
      ])
      .then((value) => {
        autoLogin = value.autoLogin !== false;
        offerSavePasskeys = value.offerSavePasskeys !== false;
        offerUsePasskeys = value.offerUsePasskeys !== false;
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
  // Per-tab ephemeral login continuation state. Metadata only, never field
  // values, and never persisted outside the service worker.
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
  function validCategory(value) {
    return ["login", "identity", "credit_card"].includes(value);
  }
  function rowCategory(row) {
    return row?.category || "login";
  }
  function wipeMap(value) {
    if (value && typeof value === "object")
      for (const key of Object.keys(value)) value[key] = "";
  }
  function multiStepFor(tabId, origin) {
    const session = multiStepSessions.get(tabId);
    if (!session) return null;
    if (Date.now() >= session.expiresAt) {
      multiStepSessions.delete(tabId);
      return null;
    }
    if (origin) {
      try {
        if (core.siteKey(origin) !== session.siteKey) {
          multiStepSessions.delete(tabId);
          return null;
        }
      } catch {
        multiStepSessions.delete(tabId);
        return null;
      }
    }
    return session;
  }
  function rememberStep(c, itemId, revision, title, step) {
    let site;
    try {
      site = core.siteKey(c.origin);
    } catch {
      return;
    }
    const previous = multiStepFor(c.tabId, c.origin);
    const stepCompleted =
      step === "username-only" ? "username" : "password";
    if (
      previous &&
      previous.itemId === itemId &&
      previous.stepCompleted === "password" &&
      stepCompleted === "username"
    )
      return;
    multiStepSessions.set(c.tabId, {
      tabId: c.tabId,
      windowId: c.windowId,
      siteKey: site,
      origin: c.origin,
      itemId,
      revision,
      title,
      stepCompleted,
      expiresAt: Date.now() + MULTI_STEP_TTL,
    });
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
    matchCategory = "login";
    multiStepSessions.clear();
    advanceEpoch();
    for (const [requestId, c] of calls) {
      retired.add(requestId);
      clearTimeout(c.timer);
      c.reject(Error("refused"));
    }
    calls.clear();
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
  async function capture(frameId = 0) {
    if (!Number.isSafeInteger(frameId) || frameId < 0) throw Error("refused");
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
      topOrigin = core.originFromURL(tab.url);
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
      results[0].result.origin !== topOrigin
    )
      throw Error("refused");
    const topDocumentId = results[0].documentId;
    let origin = topOrigin,
      documentId = topDocumentId;
    if (frameId > 0) {
      const frames = await api.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frameId] },
        func: core.probe,
      });
      if (
        frames.length !== 1 ||
        frames[0].frameId !== frameId ||
        typeof frames[0].documentId !== "string" ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(frames[0].documentId) ||
        frames[0].result?.top !== false ||
        core.originFromURL(frames[0].result?.origin) !== topOrigin
      )
        throw Error("refused");
      origin = core.originFromURL(frames[0].result.origin);
      documentId = frames[0].documentId;
    }
    const again = await api.tabs.query({ active: true, currentWindow: true });
    if (
      again.length !== 1 ||
      again[0].id !== tab.id ||
      again[0].windowId !== tab.windowId ||
      core.originFromURL(again[0].url) !== topOrigin
    )
      throw Error("refused");
    return {
      tabId: tab.id,
      windowId: tab.windowId,
      origin,
      documentId,
      frameId,
      topDocumentId,
      topOrigin,
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
    const now = await capture(expected.frameId || 0);
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
      const accepted =
        call.type === "fill"
          ? ["fill", "filled", "filled-identity", "filled-card"]
          : [expected];
      if (!accepted.includes(message.type)) {
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
    } catch {
      if (port === p && generation === epoch) {
        disconnect();
        status = "连接未获批准或已过期";
      }
    }
  }
  async function match(category = "login", frameId = 0) {
    if (!validCategory(category)) throw Error("refused");
    if (!Number.isSafeInteger(frameId) || frameId < 0) throw Error("refused");
    if (!capability || pending || pendingOTP || pendingPasskey)
      throw Error("refused");
    rows = [];
    context = null;
    matchCategory = category;
    const generation = epoch,
      c = await capture(frameId);
    await current(c);
    if (generation !== epoch) throw Error("refused");
    const fieldsToSend = fields(c);
    if (category !== "login") fieldsToSend.category = category;
    const response = await request("match", fieldsToSend);
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
          r.state !== "active" ||
          (r.category !== undefined && !validCategory(r.category)) ||
          (r.subtitle !== undefined &&
            (typeof r.subtitle !== "string" || r.subtitle.length > 1024)),
      )
    )
      throw Error("refused");
    context = c;
    rows = next.map((row) => ({
      ...row,
      category: row.category || category,
    }));
    status = `${rows.length} 个当前网站${
      category === "login" ? "登录" : category === "identity" ? "身份信息" : "信用卡"
    }`;
  }
  async function fill(itemId, revision, category = "login") {
    if (!validCategory(category)) throw Error("refused");
    const row = rows.find(
        (r) =>
          r.id === itemId &&
          r.revision === revision &&
          (category === "login"
            ? rowCategory(r) === "login"
            : rowCategory(r) === category),
      ),
      c = context,
      generation = epoch;
    if (!capability || pending || pendingOTP || pendingPasskey || !row || !c)
      throw Error("refused");
    const intent = {
      itemId,
      revision,
      category,
      tabId: c.tabId,
      windowId: c.windowId,
    };
    pending = intent;
    status =
      category === "login"
        ? quickFill
          ? "正在填充所选账号"
          : "请在原生窗口核对来源、条目与修订并批准"
        : "请在原生窗口批准本次敏感字段填充";
    let response;
    try {
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      const fieldsToSend = { ...fields(c), item_id: itemId, revision };
      if (category !== "login") fieldsToSend.category = category;
      response = await request("fill", fieldsToSend);
      if (generation !== epoch) throw Error("refused");
      await bounded(current(c), generation);
      if (generation !== epoch) throw Error("refused");
      if (category === "identity" || category === "credit_card") {
        const data =
          category === "identity" ? response.identity : response.card;
        if (!data || typeof data !== "object" || Array.isArray(data))
          throw Error("refused");
        await bounded(current(c), generation);
        intent.injectionStarted = true;
        let results;
        try {
          results = await bounded(
            api.scripting.executeScript({
              target: {
                tabId: c.tabId,
                frameIds: [c.frameId || 0],
                documentIds: [c.documentId],
              },
              func:
                category === "identity"
                  ? core.fillIdentityDocument
                  : core.fillCardDocument,
              args: [
                c.origin,
                data,
                Date.now() + 1500,
                (c.frameId || 0) > 0,
                category,
              ],
            }),
            generation,
          );
        } finally {
          wipeMap(data);
          if (category === "identity") wipeMap(response.identity);
          else wipeMap(response.card);
        }
        if (
          results.length !== 1 ||
          results[0].frameId !== (c.frameId || 0) ||
          results[0].documentId !== c.documentId ||
          results[0].result !== true
        )
          throw Error("refused");
        await bounded(current(c), generation);
        if (generation !== epoch || pending !== intent) throw Error("refused");
        intent.injectionStarted = false;
        fillUnknown = false;
        status =
          category === "identity"
            ? "本次已请求填充身份信息；请核实网站结果"
            : "本次已请求填充信用卡；请核实网站结果";
        return;
      }
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
          target: {
            tabId: c.tabId,
            frameIds: [c.frameId || 0],
            documentIds: [c.documentId],
          },
          func: core.fillDocument,
          args: [
            c.origin,
            response.username,
            response.password,
            Date.now() + 1500,
            false,
            submit,
            (c.frameId || 0) > 0,
          ],
        }),
        generation,
      );
      const filled = results[0]?.result;
      if (
        results.length !== 1 ||
        results[0].frameId !== (c.frameId || 0) ||
        results[0].documentId !== c.documentId ||
        !(filled === true || (filled && filled.ok === true))
      )
        throw Error("refused");
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.injectionStarted = false;
      fillUnknown = false;
      const step =
        filled && typeof filled === "object" && typeof filled.step === "string"
          ? filled.step
          : "combined";
      rememberStep(c, itemId, revision, row.title, step);
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
        wipeMap(response.identity);
        wipeMap(response.card);
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
  function validOTPProbe(value, c) {
    return (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).sort().join(",") ===
        "now,origin,timeOrigin,top,wall" &&
      value.top === ((c.frameId || 0) === 0) &&
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
        target: {
          tabId: c.tabId,
          frameIds: [c.frameId || 0],
          documentIds: [c.documentId],
        },
        func: core.otpDocument,
        args: [c.origin, "probe", undefined, undefined, (c.frameId || 0) > 0],
      }),
      generation,
      remaining(),
    );
    if (
      results.length !== 1 ||
      results[0].frameId !== (c.frameId || 0) ||
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
      const args = [
        c.origin,
        "fill",
        response.code,
        timing,
        (c.frameId || 0) > 0,
      ];
      response.code = "";
      let injection;
      try {
        remaining();
        intent.injectionStarted = true;
        injection = api.scripting.executeScript({
          target: {
            tabId: c.tabId,
            frameIds: [c.frameId || 0],
            documentIds: [c.documentId],
          },
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
        results[0].frameId !== (c.frameId || 0) ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      multiStepSessions.delete(c.tabId);
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
    const session = multiStepSessions.get(tabId);
    if (session && "url" in change) {
      try {
        const origin = core.originFromURL(change.url);
        if (core.siteKey(origin) !== session.siteKey)
          multiStepSessions.delete(tabId);
      } catch {
        multiStepSessions.delete(tabId);
      }
    }
    if (
      (context?.tabId === tabId ||
        pending?.tabId === tabId ||
        pendingOTP?.tabId === tabId ||
        pendingPasskey?.tabId === tabId) &&
      ("url" in change || change.status === "loading")
    )
      cancelContext();
  });
  api.tabs.onRemoved?.addListener((tabId) => {
    multiStepSessions.delete(tabId);
    if (
      context?.tabId === tabId ||
      pending?.tabId === tabId ||
      pendingOTP?.tabId === tabId ||
      pendingPasskey?.tabId === tabId
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
        Number.isSafeInteger(sender.frameId) &&
        sender.frameId >= 0 &&
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
    const c = await capture(sender.frameId);
    if (
      c.tabId !== sender.tab.id ||
      c.windowId !== sender.tab.windowId ||
      c.frameId !== sender.frameId ||
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
      const category = message.category ?? "login";
      if (!validCategory(category)) throw Error("refused");
      if (!capability || pending || pendingOTP || pendingPasskey)
        return { connected: !!capability, candidates: [] };
      if (
        !core.sameContext(c, context) ||
        matchCategory !== category ||
        Date.now() - lastMatchAt > 3000
      ) {
        await match(category, c.frameId);
        lastMatchAt = Date.now();
      }
      await current(c);
      const session =
        category === "login" ? multiStepFor(c.tabId, c.origin) : null;
      let list = rows.map((r) => ({
        id: r.id,
        revision: r.revision,
        title: r.title,
        category: rowCategory(r),
        ...(r.subtitle ? { subtitle: r.subtitle } : {}),
      }));
      if (session) {
        const index = list.findIndex((row) => row.id === session.itemId);
        if (index > 0) list.unshift(list.splice(index, 1)[0]);
      }
      return {
        connected: !!capability,
        preferredItemId: session?.itemId || "",
        preferredTitle: session?.title || "",
        step: session?.stepCompleted || "",
        candidates: list,
      };
    }
    if (
      [
        "inline-fill",
        "inline-save",
        "inline-update",
        "inline-otp",
        "inline-fill-identity",
        "inline-fill-card",
      ].includes(message.type)
    ) {
      if (!core.sameContext(context, c)) throw Error("refused");
      let category = "login";
      if (message.type === "inline-fill-identity") category = "identity";
      else if (message.type === "inline-fill-card") category = "credit_card";
      else if (message.type === "inline-fill")
        category = message.category ?? "login";
      if (!validCategory(category)) throw Error("refused");
      if (message.type === "inline-fill") {
        await fill(message.id, message.revision, category);
      } else if (message.type === "inline-fill-identity") {
        await fill(message.id, message.revision, "identity");
      } else if (message.type === "inline-fill-card") {
        await fill(message.id, message.revision, "credit_card");
      } else if (message.type === "inline-otp") {
        await otp(message.id, message.revision);
      } else {
        if ((c.frameId || 0) !== 0) throw Error("refused");
        if (message.type === "inline-update")
          await save(message.id, message.revision);
        else await save();
      }
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
            loginOverrides: { ...loginOverrides },
          };
          for (const key of [
            "autoLogin",
            "offerSavePasskeys",
            "offerUsePasskeys",
          ])
            if (typeof message[key] === "boolean") next[key] = message[key];
          if (
            /^[a-f0-9]{32}$/.test(message.id || "") &&
            typeof message.enabled === "boolean"
          )
            next.loginOverrides[message.id] = message.enabled;
          await api.storage.local.set(next);
          ({ autoLogin, offerSavePasskeys, offerUsePasskeys, loginOverrides } =
            next);
          break;
        }
        case "connect":
          void connect();
          break;
        case "disconnect":
          disconnectWithStatus("已断开");
          break;
        case "match": {
          const category = message.category ?? "login";
          if (!validCategory(category)) throw Error("refused");
          await match(category);
          break;
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
        case "fill": {
          const category = message.category ?? "login";
          if (
            typeof message.id !== "string" ||
            typeof message.revision !== "string" ||
            !validCategory(category)
          )
            throw Error("refused");
          void fill(message.id, message.revision, category).catch(() => {
            if (requestEpoch === epoch) status = "本次请求被拒绝";
          });
          break;
        }
        default:
          throw Error("refused");
      }
      return {
        connected: !!capability,
        autoLogin,
        quickFill,
        loginOverrides,
        offerSavePasskeys,
        offerUsePasskeys,
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
          category: rowCategory(r),
          ...(r.subtitle ? { subtitle: r.subtitle } : {}),
        })),
        preferredItemId: multiStepFor(context?.tabId, context?.origin)?.itemId || "",
        preferredTitle: multiStepFor(context?.tabId, context?.origin)?.title || "",
        step: multiStepFor(context?.tabId, context?.origin)?.stepCompleted || "",
        pending: !!pending || !!pendingOTP || !!pendingPasskey,
        otpPending: !!pendingOTP,
        saveBlocked: unconfirmedSave,
        origin: context?.origin || "",
      };
    };
    run().then(sendResponse, () => {
      if (requestEpoch === epoch)
        status = unconfirmedSave
          ? SAVE_UNKNOWN
          : "操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面";
      sendResponse({
        connected: !!capability,
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
        candidates: [],
        pending: !!pending || !!pendingOTP || !!pendingPasskey,
        otpPending: !!pendingOTP,
        saveBlocked: unconfirmedSave,
        origin: "",
      });
    });
    return true;
  });
})();
