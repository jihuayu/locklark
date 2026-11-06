/* Isolated world. Closed shadow UI; password values never cross the page bridge. */
(() => {
  "use strict";
  if (window !== window.top || !isSecureContext) return;
  const api = globalThis.browser || globalThis.chrome;
  let host,
    root,
    target,
    request = null,
    focusGeneration = 0;
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
  function loginInput(el) {
    return (
      el instanceof HTMLInputElement &&
      !el.disabled &&
      !el.readOnly &&
      (el.autocomplete.split(" ").includes("one-time-code") ||
        el.type === "password" ||
        el.type === "email" ||
        el.autocomplete.split(" ").includes("username") ||
        /user|login|email/i.test(el.name + " " + el.id))
    );
  }
  async function showLogins(input) {
    if (request || !loginInput(input)) return;
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
      const box = panel(target, "选择账号");
      if (!state.connected) {
        button(box, "解锁 Locklark", async () => {
          dismiss();
          await send({ type: "inline-connect" });
          if (target?.isConnected) {
            target.focus();
            void showLogins(target);
          }
        });
        button(box, "关闭", dismiss);
        return;
      }
      const otp = target.autocomplete.split(" ").includes("one-time-code");
      for (const row of state.candidates || []) {
        button(
          box,
          (otp ? "填充验证码 · " : "") + (row.title || "未命名登录"),
          () => {
            dismiss();
            void send({
              type: otp ? "inline-otp" : "inline-fill",
              id: row.id,
              revision: row.revision,
            });
          },
        );
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
      if (!state.candidates?.length) note(box, "当前网站暂无保存的登录");
      button(box, "保存当前登录", () => {
        dismiss();
        void send({ type: "inline-save" });
      });
      button(box, "关闭", dismiss);
    } catch {
      dismiss();
    }
  }
  document.addEventListener("focusin", (event) => {
    if (event.isTrusted) void showLogins(event.target);
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
  window.addEventListener("pagehide", () => {
    dismiss();
    if (request) void send({ type: "passkey-cancel", id: request.id });
    request = null;
  });
  window.addEventListener("message", async (event) => {
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
