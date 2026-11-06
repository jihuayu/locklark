/* Isolated world. Closed shadow UI; password values never cross the page bridge. */
(() => {
  "use strict";
  const core = globalThis.LocklarkCore || null;
  function frameAllowed() {
    if (
      typeof isSecureContext !== "undefined" &&
      !isSecureContext
    )
      return false;
    if (location.protocol !== "https:" || location.origin === "null")
      return false;
    if (window === window.top) return true;
    // Only same-origin frames may run the autofill UI. A cross-origin frame
    // cannot read top.location and is refused rather than risking top-site
    // credentials being offered to the embedded document.
    try {
      return (
        window.top.location.origin === location.origin &&
        window.top.location.origin !== "null"
      );
    } catch {
      return false;
    }
  }
  if (!frameAllowed()) return;
  const api = globalThis.browser || globalThis.chrome;
  let host,
    root,
    target,
    request = null,
    focusGeneration = 0,
    observer = null,
    scanTimer = null;
  const seenInputs = new WeakSet(),
    observedRoots = new WeakSet();
  const send = (message) => api.runtime.sendMessage(message);
  function dismiss() {
    host?.remove();
    host = null;
    root = null;
  }
  function panel(anchor, heading) {
    dismiss();
    host = document.createElement("div");
    host.style.cssText =
      "all:initial!important;position:fixed!important;z-index:2147483647!important;display:block!important;";
    const rect = anchor?.getBoundingClientRect();
    host.style.left =
      Math.max(8, Math.min(rect?.left ?? innerWidth - 350, innerWidth - 340)) +
      "px";
    host.style.top =
      Math.max(8, Math.min(rect?.bottom ?? 24, innerHeight - 320)) + "px";
    root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent =
      ":host{color-scheme:light dark}.panel{box-sizing:border-box;width:320px;max-height:300px;overflow:auto;background:light-dark(#fff,#1f2430);color:light-dark(#192235,#f2f4f8);border:1px solid #798298;border-radius:12px;padding:12px;box-shadow:0 8px 30px #0004;font:14px system-ui}strong{display:block;margin-bottom:8px}button{display:block;width:100%;text-align:left;font:inherit;padding:9px;border:0;border-radius:6px;background:transparent;color:inherit;cursor:pointer}button:hover,button:focus{background:light-dark(#e8efff,#344667);outline:2px solid #8daef9}p{font-size:12px;line-height:1.5;margin:4px 0}";
    const box = document.createElement("section");
    box.className = "panel";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-label", heading);
    const title = document.createElement("strong");
    title.textContent = "Locklark · " + heading;
    box.append(title);
    root.append(style, box);
    document.documentElement.append(host);
    box.addEventListener("keydown", (event) => {
      if (!event.isTrusted) return;
      if (event.key === "Escape") {
        dismiss();
        target?.focus();
        return;
      }
      if (["ArrowDown", "ArrowUp"].includes(event.key)) {
        const buttons = [...box.querySelectorAll("button")];
        const index = buttons.indexOf(root.activeElement);
        buttons[
          (index +
            (event.key === "ArrowDown" ? 1 : buttons.length - 1) +
            buttons.length) %
            buttons.length
        ]?.focus();
        event.preventDefault();
      }
    });
    return box;
  }
  function button(box, label, action) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", (e) => {
      if (e.isTrusted) action();
    });
    box.append(b);
    return b;
  }
  function note(box, text) {
    const p = document.createElement("p");
    p.textContent = text;
    box.append(p);
  }
  function hasAutocomplete(el, token) {
    return (
      (el.getAttribute && el.getAttribute("autocomplete")) ||
      el.autocomplete ||
      ""
    )
      .toLowerCase()
      .split(/\s+/)
      .includes(token);
  }
  function deepAll(selector) {
    if (core?.queryAllDeep) return core.queryAllDeep(document, selector);
    return [...document.querySelectorAll(selector)];
  }
  function eventInputTarget(event) {
    const path =
      typeof event.composedPath === "function" ? event.composedPath() : [];
    for (const node of path) {
      const tag = String((node && node.tagName) || "").toUpperCase();
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA")
        return node;
      if (
        node instanceof HTMLInputElement ||
        node instanceof HTMLSelectElement ||
        node instanceof HTMLTextAreaElement
      )
        return node;
    }
    return event.target;
  }
  function loginInput(el) {
    return (
      el instanceof HTMLInputElement &&
      !el.disabled &&
      !el.readOnly &&
      (hasAutocomplete(el, "one-time-code") ||
        el.type === "password" ||
        el.type === "email" ||
        hasAutocomplete(el, "username") ||
        /user|login|email/i.test(el.name + " " + el.id))
    );
  }
  function otpTargetFor(input) {
    if (!core?.findOTPTargets) return null;
    try {
      const found = core.findOTPTargets(document);
      return found && found.inputs.includes(input) ? found : null;
    } catch {
      return null;
    }
  }
  function enclosingForm(el) {
    try {
      if (el.form) return el.form;
      if (typeof el.closest === "function") return el.closest("form");
    } catch {}
    return null;
  }
  function suggestionKind(el) {
    const otp = otpTargetFor(el);
    if (otp) return { category: "otp", target: otp };
    const login = loginInput(el);
    const classified = core?.classifyField?.(el);
    if (classified) {
      if (classified.category === "credit_card")
        return { category: "credit_card", field: classified.field };
      if (classified.category === "identity") {
        let identityCount = 0;
        const form = enclosingForm(el);
        if (form && core?.inspectAutofillFields) {
          try {
            identityCount = core
              .inspectAutofillFields(form)
              .filter((entry) => entry.category === "identity").length;
          } catch {}
        }
        if (
          login &&
          ["email", "phone", "full_name"].includes(classified.field) &&
          identityCount < 2
        )
          return { category: "login" };
        return { category: "identity", field: classified.field };
      }
    }
    if (login) return { category: "login" };
    return null;
  }
  async function showSuggestions(input) {
    const kind = suggestionKind(input);
    if (!kind) return;
    if (kind.category === "identity" || kind.category === "credit_card") {
      await showAutofillSuggestions(input, kind.category);
      return;
    }
    await showLoginSuggestions(input, kind.category === "otp");
  }
  async function showLoginSuggestions(input, otp) {
    if (request || !(otp || loginInput(input))) return;
    target = input;
    const generation = ++focusGeneration;
    try {
      const state = await send({ type: "inline-match" });
      if (
        generation !== focusGeneration ||
        document.activeElement !== target ||
        request ||
        !state
      )
        return;
      const box = panel(target, otp ? "填充验证码" : "选择账号");
      if (!state.connected) {
        button(box, "解锁 Locklark", async () => {
          dismiss();
          await send({ type: "inline-connect" });
          if (target?.isConnected) {
            target.focus();
            void showSuggestions(target);
          }
        });
        button(box, "关闭", dismiss);
        return;
      }
      const preferred = state.preferredItemId;
      const rows = [...(state.candidates || [])];
      if (preferred) {
        const index = rows.findIndex((row) => row.id === preferred);
        if (index > 0) rows.unshift(rows.splice(index, 1)[0]);
      }
      for (const row of rows) {
        const continuing = !otp && preferred && row.id === preferred;
        const label =
          (otp ? "填充验证码 · " : continuing ? "继续登录 · " : "") +
          (row.title || "未命名登录") +
          (row.subtitle ? " · " + row.subtitle : "");
        button(box, label, () => {
          dismiss();
          void send({
            type: otp ? "inline-otp" : "inline-fill",
            id: row.id,
            revision: row.revision,
          });
        });
        if (!otp)
          button(box, "更新登录 · " + (row.title || "未命名登录"), () => {
            dismiss();
            void send({
              type: "inline-update",
              id: row.id,
              revision: row.revision,
            });
          });
      }
      if (!rows.length)
        note(
          box,
          otp ? "当前网站暂无验证码候选" : "当前网站暂无保存的登录",
        );
      if (!otp)
        button(box, "保存当前登录", () => {
          dismiss();
          void send({ type: "inline-save" });
        });
      button(box, "关闭", dismiss);
    } catch {
      dismiss();
    }
  }
  async function showAutofillSuggestions(input, category) {
    if (request) return;
    target = input;
    const generation = ++focusGeneration;
    try {
      const state = await send({ type: "inline-match", category });
      if (
        generation !== focusGeneration ||
        document.activeElement !== target ||
        request ||
        !state
      )
        return;
      const box = panel(
        target,
        category === "identity" ? "填充身份信息" : "填充信用卡",
      );
      if (!state.connected) {
        button(box, "解锁 Locklark", async () => {
          dismiss();
          await send({ type: "inline-connect" });
          if (target?.isConnected) {
            target.focus();
            void showSuggestions(target);
          }
        });
        button(box, "关闭", dismiss);
        return;
      }
      for (const row of state.candidates || []) {
        button(
          box,
          (row.title || "未命名条目") +
            (row.subtitle ? " · " + row.subtitle : ""),
          () => {
            dismiss();
            void send({
              type:
                category === "identity"
                  ? "inline-fill-identity"
                  : "inline-fill-card",
              id: row.id,
              revision: row.revision,
            });
          },
        );
      }
      if (!state.candidates?.length)
        note(
          box,
          category === "identity"
            ? "当前网站暂无保存的身份信息"
            : "当前网站暂无保存的信用卡",
        );
      button(box, "关闭", dismiss);
    } catch {
      dismiss();
    }
  }
  document.addEventListener("focusin", (event) => {
    if (!event.isTrusted) return;
    const input = eventInputTarget(event);
    if (input) void showSuggestions(input);
  });
  document.addEventListener("keydown", (event) => {
    if (
      event.isTrusted &&
      event.key === "ArrowDown" &&
      host &&
      document.activeElement === target
    ) {
      root.querySelector("button")?.focus();
      event.preventDefault();
    }
    if (event.isTrusted && event.key === "Escape") dismiss();
  });
  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    if (core?.eligibleControl) {
      try {
        if (!core.eligibleControl(el)) return false;
      } catch {}
    }
    return true;
  }
  function markExisting() {
    for (const el of deepAll("input")) {
      seenInputs.add(el);
      const tag = String(el.tagName || "").toUpperCase();
      if (tag && tag !== "INPUT") continue;
    }
  }
  async function resumeRevealed(field) {
    if (!field || host || request || !field.isConnected) return;
    if (document.visibilityState && document.visibilityState !== "visible")
      return;
    let state = null;
    try {
      state = await send({ type: "inline-match" });
    } catch {
      return;
    }
    if (!state?.preferredItemId || host || request) return;
    if (!field.isConnected) return;
    try {
      field.focus();
    } catch {
      return;
    }
    const otp = !!otpTargetFor(field);
    await showLoginSuggestions(field, otp);
  }
  function scanForRevealed(initial = false) {
    if (!document.documentElement) return;
    if (!observedRoots.has(document)) {
      observedRoots.add(document);
      observer?.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["hidden", "style", "class", "type"],
      });
    }
    const fresh = [];
    for (const el of deepAll("input")) {
      if (seenInputs.has(el)) continue;
      seenInputs.add(el);
      const tag = String(el.tagName || "").toUpperCase();
      if (tag && tag !== "INPUT") continue;
      if (!visible(el)) continue;
      const password =
        String(el.type || "").toLowerCase() === "password";
      if (password || otpTargetFor(el)) fresh.push(el);
    }
    // Observe open shadow roots discovered by the deep traversal so fields
    // revealed inside Web Components are also detected.
    for (const el of deepAll("*")) {
      if (!el.shadowRoot || el.shadowRoot.mode !== "open") continue;
      if (observedRoots.has(el.shadowRoot)) continue;
      observedRoots.add(el.shadowRoot);
      observer?.observe(el.shadowRoot, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["hidden", "style", "class", "type"],
      });
    }
    if (!initial && fresh.length) void resumeRevealed(fresh[0]);
  }
  function scheduleScan() {
    if (scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      scanForRevealed(false);
    }, 100);
  }
  function startObserver() {
    if (observer || typeof MutationObserver !== "function") return;
    observer = new MutationObserver(scheduleScan);
    markExisting();
    scanForRevealed(true);
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", startObserver, { once: true });
  else startObserver();
  window.addEventListener("pagehide", () => {
    dismiss();
    if (request) void send({ type: "passkey-cancel", id: request.id });
    request = null;
  });
  window.addEventListener("message", async (event) => {
    if (window !== window.top) return;
    const m = event.data;
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      m?.source !== "locklark-request-v1" ||
      typeof m.id !== "string" ||
      !/^[a-f0-9-]{36}$/.test(m.id)
    )
      return;
    const finish = (value) =>
      window.postMessage(
        { source: "locklark-result-v1", id: m.id, ...value },
        location.origin,
      );
    if (m.type === "cancel") {
      if (request?.id === m.id) {
        void send({ type: "passkey-cancel", id: m.id });
        request = null;
        dismiss();
      }
      return;
    }
    if (
      !["create", "get"].includes(m.type) ||
      typeof m.options !== "string" ||
      m.options.length > 32768 ||
      request ||
      document.visibilityState !== "visible"
    ) {
      finish({ fallback: true });
      return;
    }
    const feature =
      m.type === "create"
        ? "publickey-credentials-create"
        : "publickey-credentials-get";
    if (
      (document.permissionsPolicy || document.featurePolicy)?.allowsFeature(
        feature,
      ) === false
    ) {
      finish({ fallback: true });
      return;
    }
    request = { id: m.id };
    const own = request;
    let state;
    try {
      state = await send({ type: "inline-state" });
    } catch {}
    if (request !== own) return;
    if (
      !state ||
      (m.type === "create"
        ? state.offerSavePasskeys === false
        : state.offerUsePasskeys === false)
    ) {
      request = null;
      finish({ fallback: true });
      return;
    }
    const box = panel(
      null,
      m.type === "create" ? "保存 Passkey" : "使用 Passkey",
    );
    note(box, location.hostname);
    if (m.conditional) note(box, "选择后使用已保存的 Passkey 登录");
    button(
      box,
      !state.connected
        ? "解锁 Locklark 并继续"
        : m.type === "create"
          ? "保存到 Locklark"
          : "使用 Locklark 登录",
      async () => {
        dismiss();
        let submitted = false;
        try {
          if (!state.connected) {
            const connected = await send({ type: "inline-connect" });
            if (!connected?.connected) throw Error("refused");
          }
          if (request !== own) return;
          submitted = true;
          const result = await send({
            type: "passkey",
            id: m.id,
            operation: m.type,
            options: m.options,
          });
          if (request !== own) return;
          finish(
            result?.credential
              ? { credential: result.credential }
              : result?.error
                ? { error: result.error }
                : { fallback: true },
          );
        } catch {
          if (request === own)
            finish(
              m.type === "create" && submitted
                ? { error: "NotAllowedError" }
                : { fallback: true },
            );
        }
        if (request === own) request = null;
      },
    );
    button(box, "使用其他验证器", () => {
      request = null;
      dismiss();
      finish({ fallback: true });
    });
  });
})();
