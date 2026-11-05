/* No page/content-script listener exists. Only our exact popup may request work. */
if (typeof importScripts === "function") importScripts("core.js");
(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome,
    core = globalThis.LocklarkCore;
  let port = null,
    capability = "",
    context = null,
    rows = [],
    status = "未连接",
    pending = null,
    epoch = 0;
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
  function clear() {
    capability = "";
    context = null;
    rows = [];
    pending = null;
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
  function request(type, fields = {}, timeout = 35000) {
    if (!port) return Promise.reject(Error("refused"));
    const requestId = id();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        calls.delete(requestId);
        reject(Error("refused"));
        disconnect();
        status = "连接或请求已过期，请重新连接";
      }, timeout);
      calls.set(requestId, { resolve, reject, timer, type });
      port.postMessage({ v: 1, id: requestId, type, ...fields });
    });
  }
  async function capture() {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    if (
      tabs.length !== 1 ||
      !Number.isSafeInteger(tabs[0].id) ||
      tabs[0].id < 1
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
      core.originFromURL(again[0].url) !== origin
    )
      throw Error("refused");
    return { tabId: tab.id, origin, documentId: results[0].documentId };
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
    retired.clear();
    status = "请在原生窗口解锁并确认连接";
    const p = api.runtime.connectNative("org.locklark.browser");
    port = p;
    p.onDisconnect.addListener(() => {
      if (port !== p) return;
      port = null;
      clear();
      status = "原生连接已断开，请重新连接";
      void api.runtime.lastError;
    });
    p.onMessage.addListener((message) => {
      if (port !== p) return;
      if (!core.validResponse(message)) {
        disconnect();
        status = "原生协议错误，请重新连接";
        return;
      }
      if (message?.type === "locked") {
        clear();
        status = "原生金库已锁定，请重新连接并配对";
        return;
      }
      if (message.type === "unpaired") {
        clear();
        status = "扩展连接已到期，请重新连接并配对";
        return;
      }
      if (!message || message.v !== 1 || typeof message.id !== "string")
        return disconnect();
      const call = calls.get(message.id);
      if (!call) {
        if (retired.delete(message.id)) return;
        return disconnect();
      }
      calls.delete(message.id);
      clearTimeout(call.timer);
      if (message.type === "error") {
        call.reject(Error("refused"));
        return;
      }
      const expected = {
        hello: "paired",
        match: "candidates",
        fill: "fill",
        cancel: "cancelled",
      }[call.type];
      if (message.type !== expected) {
        call.reject(Error("refused"));
        disconnect();
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
      status = "已连接，请读取当前网站候选";
    } catch {
      if (port === p && generation === epoch) {
        disconnect();
        status = "连接未获批准或已过期";
      }
    }
  }
  async function match() {
    if (!capability || pending) throw Error("refused");
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
    if (!capability || pending || !row || !c) throw Error("refused");
    const intent = { itemId, revision, tabId: c.tabId };
    pending = intent;
    status = "请在原生窗口核对来源、条目与修订并批准";
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
      const results = await bounded(
        api.scripting.executeScript({
          target: { tabId: c.tabId, documentIds: [c.documentId] },
          func: core.fillDocument,
          args: [
            c.origin,
            response.username,
            response.password,
            Date.now() + 1500,
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
      status = "本次已请求填充；未自动提交";
    } catch {
      if (generation === epoch && pending === intent)
        status = "本次填充未完成；未自动重试";
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
  function cancelContext() {
    if (!context && !pending) return;
    context = null;
    rows = [];
    pending = null;
    advanceEpoch();
    status = "页面或活动标签已变化，请重新读取候选";
    if (capability) void request("cancel", { capability }).catch(() => {});
  }
  api.tabs.onActivated.addListener(cancelContext);
  api.tabs.onUpdated.addListener((tabId, change) => {
    if (
      (context?.tabId === tabId || pending?.tabId === tabId) &&
      ("url" in change || change.status === "loading")
    )
      cancelContext();
  });
  api.windows.onFocusChanged.addListener((windowId) => {
    if (windowId !== api.windows.WINDOW_ID_NONE && context) cancelContext();
  });
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!core.validSender(sender, api.runtime)) return false;
    const requestEpoch = epoch;
    const run = async () => {
      if (!message || typeof message !== "object") throw Error("refused");
      switch (message.type) {
        case "state":
          break;
        case "connect":
          void connect();
          break;
        case "disconnect":
          disconnect();
          status = "已断开";
          break;
        case "match":
          await match();
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
      return {
        connected: !!capability,
        status,
        candidates: rows.map((r) => ({
          id: r.id,
          title: r.title,
          revision: r.revision,
        })),
        pending: !!pending,
        origin: context?.origin || "",
      };
    };
    run().then(sendResponse, () => {
      if (requestEpoch === epoch)
        status = "操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面";
      sendResponse({
        connected: !!capability,
        status,
        candidates: [],
        pending: !!pending,
        origin: "",
      });
    });
    return true;
  });
})();
