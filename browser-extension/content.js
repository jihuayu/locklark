/* Isolated world. Closed shadow UI; password values never cross the page bridge. */
(() => {
  "use strict";
  const core = globalThis.LocklarkCore || null;
  // Private isolated-world DOM-policy fence. It is installed at document_start
  // in every frame the content script runs, including a cross-origin frame that
  // frameAllowed() refuses below. It only tracks whether this document's root
  // stayed stable and whether any iframe/frame sandbox attribute was ever seen.
  // It never reads vault state, sends messages, renders UI or touches the page
  // bridge, and a missing fence is never initialized on demand by a probe.
  function installCheckoutFence() {
    try {
      const g = globalThis;
      if (!g || !g.document) return;
      if (Object.prototype.hasOwnProperty.call(g, "LocklarkCheckoutFence"))
        return;
      const doc = g.document;
      const state = {
        latched: false,
        root: null,
        stable: true,
        sandboxEver: false,
      };
      function currentRoot() {
        try {
          return doc.documentElement || null;
        } catch {
          return null;
        }
      }
      function observeRoot() {
        const root = currentRoot();
        if (!state.latched) {
          if (root) {
            state.root = root;
            state.latched = true;
          }
        } else if (root !== state.root) {
          // document.open()/replacement is permanent: never recover stability.
          state.stable = false;
        }
      }
      function frameSandboxed(node) {
        if (!node || typeof node !== "object") return false;
        let tag = "";
        try {
          tag = String(node.tagName || "").toUpperCase();
        } catch {
          return false;
        }
        try {
          if (
            (tag === "IFRAME" || tag === "FRAME") &&
            typeof node.hasAttribute === "function" &&
            node.hasAttribute("sandbox")
          )
            return true;
        } catch {}
        try {
          if (typeof node.querySelectorAll === "function")
            for (const selector of ["iframe", "frame"]) {
              let found;
              try {
                found = node.querySelectorAll(selector);
              } catch {
                continue;
              }
              for (const el of found || [])
                if (
                  el &&
                  typeof el.hasAttribute === "function" &&
                  el.hasAttribute("sandbox")
                )
                  return true;
            }
        } catch {}
        return false;
      }
      function markSandbox(node) {
        if (!state.sandboxEver && frameSandboxed(node)) state.sandboxEver = true;
      }
      observeRoot();
      markSandbox(doc);
      const snapshot = function () {
        observeRoot();
        return Object.freeze({
          document_stable: state.latched === true && state.stable === true,
          sandbox_ever: state.sandboxEver === true,
        });
      };
      Object.freeze(snapshot);
      try {
        Object.defineProperty(g, "LocklarkCheckoutFence", {
          value: snapshot,
          writable: false,
          configurable: false,
          enumerable: false,
        });
      } catch {
        return;
      }
      if (typeof g.MutationObserver !== "function") return;
      try {
        const observer = new g.MutationObserver((records) => {
          try {
            observeRoot();
            for (const record of records || []) {
              if (!record) continue;
              if (record.type === "attributes") {
                if (record.attributeName !== "sandbox") continue;
                // An immediate add/remove race still shows a non-null oldValue.
                if (record.oldValue !== null && record.oldValue !== undefined)
                  state.sandboxEver = true;
                const target = record.target;
                if (
                  target &&
                  typeof target.hasAttribute === "function" &&
                  target.hasAttribute("sandbox")
                )
                  state.sandboxEver = true;
              } else if (record.type === "childList") {
                for (const node of record.addedNodes || []) markSandbox(node);
                for (const node of record.removedNodes || []) markSandbox(node);
              }
            }
          } catch {}
        });
        observer.observe(doc, {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ["sandbox"],
          attributeOldValue: true,
        });
      } catch {}
      if (typeof doc.addEventListener === "function")
        doc.addEventListener(
          "DOMContentLoaded",
          () => {
            try {
              observeRoot();
              markSandbox(doc);
            } catch {}
          },
          { once: true },
        );
    } catch {}
  }
  installCheckoutFence();
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
  const nativeValue = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  const send = (message) => api.runtime.sendMessage(message);
  // Paste protection keeps at most one metadata-only site-link observation per
  // document. A stale observation is unknown, never "unlinked".
  const SITE_LINK_TTL = 5 * 60 * 1000;
  let siteLink = { origin: "", linked: null, at: 0 };
  function rememberSiteLink(reply) {
    const linked =
      reply && reply.connected === true && typeof reply.siteLinked === "boolean"
        ? reply.siteLinked
        : null;
    siteLink = { origin: location.origin, linked, at: Date.now() };
  }
  function siteLinkedForPaste() {
    if (siteLink.origin !== location.origin) return null;
    if (Date.now() - siteLink.at > SITE_LINK_TTL) return null;
    return siteLink.linked;
  }
  const settingsReady = (async () => {
    try {
      const value = await api.storage?.local?.get?.([
        "showInlineMenu",
        "showInlineGenerator",
        "disabledInlineMenuOrigins",
        "pasteProtection",
      ]);
      if (value && typeof value === "object") {
        siteSettings.showInlineMenu = value.showInlineMenu !== false;
        siteSettings.showInlineGenerator = value.showInlineGenerator !== false;
        siteSettings.pasteProtection = value.pasteProtection !== false;
        siteSettings.disabledInlineMenuOrigins = Array.isArray(
          value.disabledInlineMenuOrigins,
        )
          ? value.disabledInlineMenuOrigins.filter(
              (origin) => typeof origin === "string",
            )
          : [];
      }
    } catch {}
  })();
  let host,
    root,
    target,
    request = null,
    conditionalRequest = null,
    conditionalGeneration = 0,
    capabilityProbe = { at: 0, supported: false, pending: null },
    focusGeneration = 0,
    panelAnchor = null,
    panelHasAnchor = false,
    panelWidth = 320,
    pendingHost = null,
    pendingStageId = "",
    pendingDismissedForPasskey = false,
    toastHost = null,
    toastTimer = null,
    pendingCheckInFlight = false,
    stageCooldownSignature = "",
    stageCooldownAt = 0,
    lastEditedCredential = null,
    mutationCheckTimer = null,
    generatorSerial = 0,
    siteSettings = {
      showInlineMenu: true,
      showInlineGenerator: true,
      pasteProtection: true,
      disabledInlineMenuOrigins: [],
    },
    observer = null,
    scanTimer = null;
  function element(tag, textValue, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (textValue !== undefined) node.textContent = textValue;
    return node;
  }
  function inputValue(el) {
    try {
      return nativeValue?.get?.call(el) || "";
    } catch {
      return "";
    }
  }
  const seenInputs = new WeakSet(),
    observedRoots = new WeakSet();
  function dismiss() {
    if (host) host.remove();
    host = null;
    root = null;
    panelAnchor = null;
    panelHasAnchor = false;
    panelWidth = 320;
  }
  function setPanelPosition() {
    if (!host || !panelHasAnchor) return;
    const anchor = panelAnchor;
    const rect = anchor?.getBoundingClientRect?.();
    if (
      !anchor?.isConnected ||
      !rect ||
      rect.width === 0 ||
      rect.height === 0
    ) {
      dismiss();
      return;
    }
    const left = Math.max(
      8,
      Math.min(rect.left, Math.max(8, innerWidth - panelWidth - 8)),
    );
    let top = rect.bottom + 4;
    const height = host.getBoundingClientRect().height || 320;
    if (top + height > innerHeight - 8)
      top = Math.max(8, rect.top - height - 4);
    host.style.left = left + "px";
    host.style.top = top + "px";
  }
  function panel(anchor, heading, wide) {
    dismiss();
    panelAnchor = anchor || null;
    panelHasAnchor = !!anchor;
    panelWidth = wide ? 360 : 320;
    host = element("div");
    host.style.cssText =
      "all:initial!important;position:fixed!important;z-index:2147483647!important;display:block!important;";
    root = host.attachShadow({ mode: "closed" });
    const style = element("style");
    style.textContent =
      ":host{color-scheme:light dark}.panel{box-sizing:border-box;width:" +
      panelWidth +
      "px;max-height:380px;overflow:auto;background:light-dark(#fff,#1f2430);color:light-dark(#192235,#f2f4f8);border:1px solid #798298;border-radius:12px;padding:12px;box-shadow:0 8px 30px #0004;font:14px system-ui}strong{display:block;margin-bottom:8px}button{display:block;width:100%;text-align:left;font:inherit;padding:9px;border:0;border-radius:6px;background:transparent;color:inherit;cursor:pointer}button:hover,button:focus{background:light-dark(#e8efff,#344667);outline:2px solid #8daef9}button:disabled{opacity:.55;cursor:default}p{font-size:12px;line-height:1.5;margin:4px 0}label{display:block;font-size:12px;margin:6px 0}label.check{display:flex;align-items:center;gap:6px}input[type=range]{width:100%;margin:6px 0}input[type=text],select{box-sizing:border-box;width:100%;font:inherit;padding:6px;border:1px solid #798298;border-radius:6px;background:light-dark(#fff,#1f2430);color:inherit}.row{display:flex;align-items:center;justify-content:space-between;gap:8px}.mono{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;overflow-wrap:anywhere;padding:6px;border-radius:6px;background:light-dark(#f1f4f9,#2a3140)}.badge{display:inline-block;font-size:11px;padding:2px 6px;border-radius:999px;background:light-dark(#e6f4ec,#1f3b2c);color:light-dark(#17633a,#a6e2bd)}.status{color:light-dark(#52645a,#b9c5d3)}";
    const box = element("section");
    box.className = "panel";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-label", heading);
    const title = element("strong", "Locklark · " + heading);
    box.append(title);
    root.append(style, box);
    document.documentElement.append(host);
    if (!anchor) {
      host.style.left =
        Math.max(8, innerWidth - panelWidth - 8) + "px";
      host.style.top = "24px";
    }
    box.addEventListener("keydown", (event) => {
      if (!event.isTrusted) return;
      if (event.key === "Escape") {
        dismiss();
        target?.focus();
        return;
      }
      if (
        ["ArrowDown", "ArrowUp"].includes(event.key) &&
        (event.target === box || event.target?.tagName === "BUTTON")
      ) {
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
    setPanelPosition();
    return box;
  }
  function button(box, label, action) {
    const b = element("button", label);
    b.type = "button";
    b.addEventListener("click", (e) => {
      if (e.isTrusted) void action();
    });
    box.append(b);
    return b;
  }
  function note(box, textValue, className) {
    const p = element("p", textValue, className);
    box.append(p);
    return p;
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
  function fieldLabel(el) {
    return [el.name, el.id, el.placeholder, el.getAttribute?.("aria-label")]
      .filter((value) => typeof value === "string")
      .join(" ")
      .toLowerCase();
  }
  function ignored(el) {
    try {
      return (
        el.hasAttribute?.("data-1p-ignore") ||
        el.hasAttribute?.("data-locklark-ignore") ||
        !!el.closest?.("[data-1p-ignore],[data-locklark-ignore]")
      );
    } catch {
      return false;
    }
  }
  function visibleField(el) {
    if (
      !(el instanceof HTMLInputElement) ||
      !el.isConnected ||
      el.disabled ||
      el.readOnly ||
      ignored(el)
    )
      return false;
    try {
      if (el.matches(":disabled")) return false;
      if (el.closest("[hidden],[inert],[aria-hidden='true']")) return false;
      for (let n = el; n instanceof Element; n = n.parentElement) {
        const style = getComputedStyle(n);
        if (
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          Number(style.opacity) === 0
        )
          return false;
      }
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    } catch {
      return false;
    }
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
  // document.activeElement is retargeted to the host for controls inside a
  // shadow root, so a focused shadow input never matches its own panel anchor.
  // Descend only through open roots (shadowRoot.activeElement); a closed root
  // exposes no shadowRoot and therefore stays opaque at its host.
  function deepActiveElement() {
    let active = document.activeElement || null;
    for (let depth = 0; active && depth < 20; depth++) {
      let inner = null;
      try {
        inner = active.shadowRoot?.activeElement || null;
      } catch {
        inner = null;
      }
      if (!inner || inner === active) break;
      active = inner;
    }
    return active;
  }
  function autocompleteTokens(el) {
    return String(
      (el && el.getAttribute && el.getAttribute("autocomplete")) ||
        el?.autocomplete ||
        "",
    )
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
  }
  // Conditional Passkey UI is limited to a focused, visible, writable input
  // whose autocomplete token list asks for WebAuthn.
  function conditionalField(el) {
    if (!(el instanceof HTMLInputElement) || !visibleField(el)) return false;
    const type = String(el.type || "text").toLowerCase();
    if (
      [
        "password",
        "hidden",
        "checkbox",
        "radio",
        "submit",
        "button",
        "reset",
        "file",
        "image",
        "range",
        "color",
      ].includes(type)
    )
      return false;
    return autocompleteTokens(el).includes("webauthn");
  }
  function conditionalChoiceLabel(entry) {
    const display = typeof entry.display_name === "string" ? entry.display_name.trim() : "";
    const user = typeof entry.user_name === "string" ? entry.user_name.trim() : "";
    const title = typeof entry.title === "string" ? entry.title.trim() : "";
    const account = display || user || title || "Passkey";
    const secondary =
      user && user !== account
        ? user
        : typeof entry.rp_id === "string"
          ? entry.rp_id
          : "";
    return secondary ? account + " · " + secondary : account;
  }
  // Public sibling hint: a short, non-secret slice of the credential ID so
  // two accounts with identical display labels stay distinguishable.
  function shortCredentialHint(credentialID) {
    return typeof credentialID === "string" && credentialID.length > 12
      ? credentialID.slice(0, 6) + "…" + credentialID.slice(-4)
      : "";
  }
  function clearConditional() {
    conditionalRequest = null;
    conditionalGeneration++;
  }
  async function conditionalCapabilitySupported() {
    if (Date.now() - capabilityProbe.at < 2000) return capabilityProbe.supported;
    if (!capabilityProbe.pending)
      capabilityProbe.pending = (async () => {
        let supported = false;
        try {
          const state = await send({ type: "inline-state" });
          supported = state?.passkeyConditionalSupported === true;
        } catch {}
        capabilityProbe.at = Date.now();
        capabilityProbe.supported = supported;
        capabilityProbe.pending = null;
        return supported;
      })();
    return capabilityProbe.pending;
  }
  async function replyConditionalCapability(id) {
    const supported = (await conditionalCapabilitySupported()) === true;
    // Only a boolean ever leaves the isolated world for the page bridge.
    window.postMessage(
      { source: "locklark-capability-v1", id, conditional: supported },
      location.origin,
    );
  }
  // WebAuthn Signal API hints are fire-and-forget: the isolated world forwards
  // one bounded, well-formed public RP hint and never posts anything back to
  // the page. A foreign source/origin, an unexpected key or an unbounded or
  // malformed document is dropped without a trace.
  function forwardSignalHint(data) {
    if (!data || typeof data !== "object") return;
    if (Object.keys(data).sort().join(",") !== "id,options,source") return;
    if (data.source !== "locklark-signal-v1") return;
    if (typeof data.id !== "string" || !/^[a-f0-9-]{36}$/.test(data.id)) return;
    if (typeof data.options !== "string" || data.options.length > 32768) return;
    const options = core?.passkeySignalOptions
      ? core.passkeySignalOptions(data.options)
      : "";
    if (!options) return;
    try {
      const sent = send({ type: "passkey-signal", options });
      if (sent && typeof sent.catch === "function") sent.catch(() => {});
    } catch {}
  }
  function finishConditional(call, result) {
    if (conditionalRequest !== call) return;
    clearConditional();
    call.finish(
      result?.credential
        ? { credential: result.credential }
        : result?.error
          ? { error: result.error }
          : { fallback: true },
    );
  }
  function fallbackConditional(call) {
    if (conditionalRequest !== call) return;
    clearConditional();
    dismiss();
    try {
      void send({ type: "passkey-cancel", id: call.id });
    } catch {}
    call.finish({ fallback: true });
  }
  async function sendConditionalSelection(message, call) {
    let result;
    try {
      result = await send(message);
    } catch {}
    if (conditionalRequest !== call) return;
    finishConditional(call, result);
  }
  async function showConditionalAccounts(anchor) {
    const call = conditionalRequest;
    if (!call || document.visibilityState !== "visible") return;
    if (!conditionalField(anchor)) return;
    // Focus guard: the anchor must still be the real focused control, which
    // may live inside an open shadow root.
    if (deepActiveElement() !== anchor || !anchor.isConnected) return;
    const generation = ++conditionalGeneration;
    let listed;
    try {
      listed = await send({
        type: "passkey-conditional-open",
        id: call.id,
        options: call.options,
      });
    } catch {}
    if (conditionalRequest !== call || generation !== conditionalGeneration)
      return;
    if (deepActiveElement() !== anchor || !anchor.isConnected) return;
    if (document.visibilityState !== "visible") return;
    if (!conditionalField(anchor)) return;
    if (!listed || listed.fallback === true || !Array.isArray(listed.passkeys)) {
      fallbackConditional(call);
      return;
    }
    if (pendingHost) {
      dismissPending();
      pendingDismissedForPasskey = true;
    }
    const box = panel(anchor, "Passkey 账号");
    box.setAttribute("data-locklark-conditional", "passkey");
    note(box, location.hostname);
    const entries = listed.passkeys.slice(0, 50);
    const labelCounts = new Map();
    for (const entry of entries) {
      const label = conditionalChoiceLabel(entry);
      labelCounts.set(label, (labelCounts.get(label) || 0) + 1);
    }
    for (const entry of entries) {
      const label = conditionalChoiceLabel(entry);
      const childRevision =
        typeof entry.credential_revision === "string" &&
        /^[a-f0-9]{64}$/.test(entry.credential_revision)
          ? entry.credential_revision
          : "";
      const hint = (labelCounts.get(label) || 0) > 1
        ? shortCredentialHint(entry.credential_id)
        : "";
      const choice = element("button", hint ? label + " · " + hint : label);
      choice.type = "button";
      choice.setAttribute(
        "data-locklark-passkey-choice",
        entry.item_id || entry.credential_id,
      );
      choice.setAttribute("data-locklark-passkey-credential", entry.credential_id);
      choice.setAttribute("data-locklark-passkey-revision", entry.revision);
      if (childRevision)
        choice.setAttribute(
          "data-locklark-passkey-credential-revision",
          childRevision,
        );
      choice.addEventListener("click", (event) => {
        if (!event.isTrusted) return;
        if (conditionalRequest !== call) return;
        if (document.visibilityState !== "visible") return;
        dismiss();
        void sendConditionalSelection(
          {
            type: "passkey-conditional-select",
            id: call.id,
            item_id: entry.item_id,
            revision: entry.revision,
            credential_id: entry.credential_id,
            ...(childRevision ? { credential_revision: childRevision } : {}),
          },
          call,
        );
      });
      box.append(choice);
    }
    if (!entries.length) note(box, "当前网站暂无已保存的 Passkey");
    if (listed.truncated === true) {
      const native = element("button", "使用系统 Passkey 选择器");
      native.type = "button";
      native.setAttribute("data-locklark-passkey-native", "true");
      native.addEventListener("click", (event) => {
        if (!event.isTrusted) return;
        if (conditionalRequest !== call) return;
        if (document.visibilityState !== "visible") return;
        dismiss();
        void sendConditionalSelection(
          { type: "passkey-conditional-select", id: call.id, native: true },
          call,
        );
      });
      box.append(native);
    }
    button(box, "使用其他验证器", () => fallbackConditional(call));
  }
  function loginInput(el) {
    return (
      el instanceof HTMLInputElement &&
      visibleField(el) &&
      (hasAutocomplete(el, "one-time-code") ||
        el.type === "password" ||
        el.type === "email" ||
        hasAutocomplete(el, "username") ||
        /user|login|email/i.test(el.name + " " + el.id))
    );
  }
  function passwordInputs(scope) {
    try {
      return [...scope.querySelectorAll('input[type="password"]')].filter(
        loginInput,
      );
    } catch {
      return [];
    }
  }
  function isCurrentPassword(el) {
    return (
      hasAutocomplete(el, "current-password") ||
      /current|old|existing/i.test(fieldLabel(el))
    );
  }
  function isConfirmPassword(el) {
    return /confirm|repeat|verify|again|retype/i.test(fieldLabel(el));
  }
  function isNewPasswordInput(el) {
    if (!(el instanceof HTMLInputElement) || el.type !== "password")
      return false;
    if (!loginInput(el)) return false;
    const form = el.form;
    if (hasAutocomplete(el, "new-password")) return true;
    if (
      /new.?pass|create.?pass|confirm.?pass|repeat.?pass|sign.?up|register|reset.?pass|change.?pass/i.test(
        fieldLabel(el) + " " + (form?.getAttribute?.("action") || ""),
      )
    )
      return true;
    const fields = passwordInputs(form || document);
    if (fields.length === 2 || fields.length === 3) {
      const current = fields.find(isCurrentPassword);
      return el !== current;
    }
    return false;
  }
  function passwordForm(el) {
    return el?.form || el?.closest?.("form") || null;
  }
  function usernameField(scope, form) {
    const pool = [...scope.querySelectorAll("input")].filter(
      (el) =>
        visibleField(el) &&
        ["text", "email"].includes(el.type) &&
        (!form || el.form === form),
    );
    const strong = pool.filter(
      (el) =>
        hasAutocomplete(el, "username") || hasAutocomplete(el, "email"),
    );
    const email = pool.filter((el) => el.type === "email");
    const semantic = pool.filter((el) =>
      /user|login|email|account|identifier/i.test(fieldLabel(el)),
    );
    return strong[0] || email[0] || semantic[0] || null;
  }
  function validCredential(value, allowEmpty) {
    if (typeof value !== "string") return false;
    if (!allowEmpty && value.length === 0) return false;
    return (
      value.length <= 16384 &&
      (!value.isWellFormed || value.isWellFormed())
    );
  }
  // Captures the password that a signup/change/login form is about to submit.
  // It always prefers the new-password value over the current-password value.
  function extractCredentials(rootNode) {
    let scope =
      rootNode instanceof HTMLFormElement
        ? rootNode
        : rootNode?.closest?.("form") || null;
    if (!scope && rootNode instanceof Element && rootNode.querySelectorAll)
      scope = rootNode;
    const form = scope instanceof HTMLFormElement ? scope : null;
    if (!scope) scope = document;
    const passwords = passwordInputs(scope);
    if (passwords.length < 1 || passwords.length > 3) return null;
    let currentPass = null,
      newPass = null,
      confirmPass = null,
      isNewPassword = false;
    if (passwords.length === 3) {
      currentPass = passwords[0];
      newPass = passwords[1];
      confirmPass = passwords[2];
      isNewPassword = true;
    } else if (passwords.length === 2) {
      if (isCurrentPassword(passwords[0]) && !isConfirmPassword(passwords[1])) {
        currentPass = passwords[0];
        newPass = passwords[1];
        isNewPassword = true;
      } else {
        newPass = passwords[0];
        confirmPass = passwords[1];
        isNewPassword = true;
      }
    } else {
      newPass = passwords[0];
      isNewPassword = isNewPasswordInput(passwords[0]);
    }
    const password = inputValue(newPass);
    const confirmation = confirmPass ? inputValue(confirmPass) : "";
    if (!validCredential(password, false)) return null;
    if (confirmation !== "" && confirmation !== password) return null;
    const user = usernameField(form || scope, form);
    const username = user ? inputValue(user) : "";
    if (!validCredential(username, true)) return null;
    return {
      username,
      password,
      isNewPassword,
      isPasswordChange: !!currentPass && !!newPass,
    };
  }
  function schedulePendingCheck() {
    setTimeout(() => void checkPendingSave(), 300);
  }
  function stageSnapshot(snapshot) {
    if (
      !snapshot ||
      !validCredential(snapshot.password, false) ||
      !validCredential(snapshot.username, true)
    )
      return;
    const signature = [
      snapshot.username,
      snapshot.password,
      snapshot.isNewPassword === true,
      snapshot.isPasswordChange === true,
    ].join("\u0000");
    const now = Date.now();
    if (signature === stageCooldownSignature && now - stageCooldownAt < 2000)
      return;
    stageCooldownSignature = signature;
    stageCooldownAt = now;
    lastEditedCredential = null;
    void send({
      type: "inline-stage-save",
      username: snapshot.username,
      password: snapshot.password,
      isNewPassword: snapshot.isNewPassword === true,
      isPasswordChange: snapshot.isPasswordChange === true,
    })
      .then(() => schedulePendingCheck())
      .catch(() => {});
  }
  function stageFrom(rootNode) {
    const snapshot = extractCredentials(rootNode);
    if (snapshot) stageSnapshot(snapshot);
  }
  function findPasswordContainer(node) {
    const form = node?.closest?.("form");
    if (form) return form;
    let parent = node?.parentElement || null;
    for (let i = 0; parent && i < 8; i++, parent = parent.parentElement)
      if (passwordInputs(parent).length) return parent;
    return null;
  }
  function submitLike(buttonNode) {
    if (!(buttonNode instanceof Element)) return false;
    const type = (
      buttonNode.getAttribute?.("type") ||
      buttonNode.type ||
      ""
    ).toLowerCase();
    if (type === "submit") return true;
    const label = [
      buttonNode.textContent,
      buttonNode.value,
      buttonNode.getAttribute?.("aria-label"),
      buttonNode.id,
    ]
      .filter((value) => typeof value === "string")
      .join(" ");
    return /登录|登陆|注册|继续|下一步|提交|保存|更新|修改|sign|log.?in|submit|continue|next|register|sign.?up|create|save|update|change/i.test(
      label,
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
    return showLogins(input, otp);
  }

  async function showLogins(input, otp) {
    if (request || !loginInput(input)) return;
    if (
      input.closest?.("[data-locklark-ignore]") ||
      input.getAttribute?.("data-locklark-ignore") !== null
    )
      return;
    await settingsReady;
    if (
      siteSettings.showInlineMenu === false ||
      siteSettings.disabledInlineMenuOrigins.includes(location.origin)
    )
      return;
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
      rememberSiteLink(state);
      if (state.neverSaveForOrigin || state.suppressInline) return;
      const anchor = target;
      const isPassword = anchor.type === "password";
      const newPassword = isPassword && isNewPasswordInput(anchor);
      let suggestion = null;
      if (newPassword) {
        try {
          suggestion = await send({
            type: "inline-generate",
            recordHistory: false,
            ...generationParams(state.generatorDefaults),
          });
        } catch {}
        if (
          generation !== focusGeneration ||
          document.activeElement !== target ||
          request ||
          !target?.isConnected
        )
          return;
      }
      const box = panel(anchor, otp ? "填充验证码" : "选择账号");
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
      if (newPassword) {
        const params = generationParams(state.generatorDefaults);
        if (typeof suggestion?.password === "string")
          note(box, "建议密码：" + suggestion.password, "mono");
        button(box, "填充建议密码", async () => {
          dismiss();
          try {
            await send({
              type: "inline-generate-fill",
              ...params,
              password: suggestion.password,
              profile: suggestion.profile,
              username: usernameField(passwordForm(anchor) || document, passwordForm(anchor))
                ? inputValue(
                    usernameField(
                      passwordForm(anchor) || document,
                      passwordForm(anchor),
                    ),
                  )
                : "",
            });
          } catch {}
        });
        button(box, "生成强密码…", () => void showGeneratorPanel(anchor));
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
      if (isPassword && !newPassword)
        button(box, "生成密码…", () => void showGeneratorPanel(anchor));
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

  function clampInteger(value, min, max, fallback) {
    return Number.isSafeInteger(value)
      ? Math.min(max, Math.max(min, value))
      : fallback;
  }
  const separators = {
    hyphens: "连字符 -",
    spaces: "空格",
    periods: "句点 .",
    commas: "逗号 ,",
    underscores: "下划线 _",
    numbers: "数字",
    "numbers-and-symbols": "数字和符号",
  };
  function generationParams(defaults = {}) {
    const mode = ["random", "memorable", "pin"].includes(defaults.mode)
      ? defaults.mode
      : "random";
    if (mode === "memorable")
      return {
        mode,
        length: clampInteger(defaults.wordCount, 3, 8, 4),
        digits: defaults.digits === true,
        capitalize: defaults.capitalize !== false,
        separator: Object.hasOwn(separators, defaults.separator)
          ? defaults.separator
          : "hyphens",
      };
    if (mode === "pin")
      return { mode, length: clampInteger(defaults.pinLength, 4, 12, 6) };
    return {
      mode,
      length: clampInteger(defaults.length, 16, 64, 24),
      digits: defaults.digits !== false,
      symbols: defaults.symbols !== false,
    };
  }
  async function copyPassword(value) {
    if (!value) return false;
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {}
    try {
      const area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
      document.documentElement.append(area);
      area.select();
      const copied = document.execCommand("copy");
      area.remove();
      return copied === true;
    } catch {
      return false;
    }
  }
  async function showGeneratorPanel(anchorInput) {
    if (
      request ||
      !(anchorInput instanceof HTMLInputElement) ||
      anchorInput.type !== "password"
    )
      return;
    target = anchorInput;
    let state = {};
    try {
      state = await send({ type: "inline-state" });
    } catch {}
    if (!anchorInput.isConnected) return;
    const defaults = state?.generatorDefaults || {};
    const local = {
      mode: ["random", "memorable", "pin"].includes(defaults.mode)
        ? defaults.mode
        : "random",
      lengths: {
        random: clampInteger(defaults.length, 16, 64, 24),
        memorable: clampInteger(defaults.wordCount, 3, 8, 4),
        pin: clampInteger(defaults.pinLength, 4, 12, 6),
      },
      digits: defaults.digits !== false,
      symbols: defaults.symbols !== false,
      capitalize: defaults.capitalize !== false,
      separator: Object.hasOwn(separators, defaults.separator)
        ? defaults.separator
        : "hyphens",
    };
    const box = panel(anchorInput, "生成密码", true);
    const modeRow = element("label", "模式");
    const modeSelect = element("select");
    for (const [value, label] of [
      ["random", "随机字符"],
      ["memorable", "易记词组"],
      ["pin", "PIN 码"],
    ]) {
      const option = element("option", label);
      option.value = value;
      modeSelect.append(option);
    }
    modeSelect.value = local.mode;
    modeRow.append(modeSelect);
    box.append(modeRow);
    const controls = element("div");
    box.append(controls);
    const previewWrap = element("div", undefined, "row");
    const previewEl = element("code", "…", "mono");
    const entropyEl = element("span", "", "badge");
    previewWrap.append(previewEl, entropyEl);
    box.append(previewWrap);
    let currentPreview = "";
    let currentProfile = null;
    let previewTimer = null;
    let statusEl = null;
    const params = () => {
      if (local.mode === "random")
        return {
          mode: "random",
          length: local.lengths.random,
          digits: local.digits,
          symbols: local.symbols,
        };
      if (local.mode === "memorable")
        return {
          mode: "memorable",
          length: local.lengths.memorable,
          digits: false,
          capitalize: local.capitalize,
          separator: local.separator,
        };
      return { mode: "pin", length: local.lengths.pin };
    };
    function setStatus(textValue) {
      if (statusEl) statusEl.textContent = textValue;
    }
    async function generatePreview() {
      const serial = ++generatorSerial;
      try {
        const result = await send({
          type: "inline-generate",
          recordHistory: false,
          ...params(),
        });
        if (serial !== generatorSerial || !box.isConnected) return;
        if (typeof result?.password === "string" && result.password.length >= 4) {
          currentPreview = result.password;
          currentProfile = result.profile || null;
          previewEl.textContent = currentPreview;
          entropyEl.textContent =
            String(result.profile?.entropy_bits_floor ?? "?") + " bits";
        } else setStatus("生成失败，请重试");
      } catch {
        if (serial === generatorSerial) setStatus("生成失败，请重试");
      }
    }
    function scheduleGenerate() {
      clearTimeout(previewTimer);
      previewTimer = setTimeout(() => void generatePreview(), 120);
    }
    function checkbox(label, checked, change) {
      const row = element("label", undefined, "check");
      const toggle = element("input");
      toggle.type = "checkbox";
      toggle.checked = checked;
      toggle.addEventListener("change", () => change(toggle.checked));
      row.append(toggle, document.createTextNode(" " + label));
      return row;
    }
    function rebuildControls() {
      controls.replaceChildren();
      const range = element("input");
      range.type = "range";
      range.min = String(
        local.mode === "random" ? 16 : local.mode === "pin" ? 4 : 3,
      );
      range.max = String(
        local.mode === "random" ? 64 : local.mode === "pin" ? 12 : 8,
      );
      range.value = String(local.lengths[local.mode]);
      const label = element(
        "label",
        local.mode === "memorable" ? "词组数" : "长度",
      );
      const value = element("span", String(local.lengths[local.mode]));
      const line = element("div", undefined, "row");
      line.append(label, value);
      const rangeRow = element("div");
      rangeRow.append(line, range);
      controls.append(rangeRow);
      range.addEventListener("input", () => {
        local.lengths[local.mode] = Number(range.value);
        value.textContent = range.value;
        scheduleGenerate();
      });
      if (local.mode === "random") {
        controls.append(
          checkbox("含数字", local.digits, (checked) => {
            local.digits = checked;
            scheduleGenerate();
          }),
        );
        controls.append(
          checkbox("含符号", local.symbols, (checked) => {
            local.symbols = checked;
            scheduleGenerate();
          }),
        );
      } else if (local.mode === "memorable") {
        controls.append(
          checkbox("首字母大写", local.capitalize, (checked) => {
            local.capitalize = checked;
            scheduleGenerate();
          }),
        );
        const separatorRow = element("label", "分隔符");
        const separatorSelect = element("select");
        for (const [valueName, labelText] of Object.entries(separators)) {
          const option = element("option", labelText);
          option.value = valueName;
          separatorSelect.append(option);
        }
        separatorSelect.value = local.separator;
        separatorSelect.addEventListener("change", () => {
          local.separator = separatorSelect.value;
          scheduleGenerate();
        });
        separatorRow.append(separatorSelect);
        controls.append(separatorRow);
      }
    }
    rebuildControls();
    modeSelect.addEventListener("change", () => {
      local.mode = ["random", "memorable", "pin"].includes(modeSelect.value)
        ? modeSelect.value
        : "random";
      rebuildControls();
      scheduleGenerate();
    });
    const fillButton = button(box, "填充密码", async () => {
      fillButton.disabled = true;
      try {
        const result = await send({
          type: "inline-generate-fill",
          ...params(),
          password: currentPreview || undefined,
          profile: currentProfile || undefined,
          username: (() => {
            const form = passwordForm(anchorInput);
            const field = usernameField(form || document, form);
            return field ? inputValue(field) : "";
          })(),
        });
        if (typeof result?.password === "string") {
          currentPreview = result.password;
          currentProfile = result.profile || currentProfile;
          previewEl.textContent = currentPreview;
          if (result.profile)
            entropyEl.textContent =
              String(result.profile.entropy_bits_floor ?? "?") + " bits";
        }
        setStatus(
          result?.filledCount > 0
            ? "已填充密码，请确认后提交"
            : "未能自动填充，请复制密码",
        );
      } catch {
        setStatus("填充失败，请复制密码");
      } finally {
        fillButton.disabled = false;
      }
    });
    button(box, "重新生成", () => void generatePreview());
    button(box, "复制", async () => {
      setStatus((await copyPassword(currentPreview)) ? "已复制" : "复制失败");
    });
    statusEl = note(box, "", "status");
    button(box, "关闭", dismiss);
    void generatePreview();
  }

  document.addEventListener("focusin", (event) => {
    if (!event.isTrusted) return;
    const input = eventInputTarget(event);
    if (!input) return;
    if (
      conditionalRequest &&
      document.visibilityState === "visible" &&
      conditionalField(input)
    ) {
      void showConditionalAccounts(input);
      return;
    }
    void showSuggestions(input);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") return;
    if (conditionalRequest) dismiss();
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
  document.addEventListener(
    "submit",
    (event) => stageFrom(event.target),
    true,
  );
  document.addEventListener(
    "keydown",
    (event) => {
      if (
        !event.isTrusted ||
        !["Enter", "NumpadEnter"].includes(event.key) ||
        !loginInput(event.target)
      )
        return;
      const form = passwordForm(event.target);
      if (event.target.type !== "password" && !passwordInputs(form || document).length)
        return;
      stageFrom(event.target);
    },
    true,
  );
  document.addEventListener(
    "click",
    (event) => {
      if (!event.isTrusted) return;
      const buttonNode = event.target?.closest?.(
        'button[type="submit"],input[type="submit"],button',
      );
      if (!buttonNode || !submitLike(buttonNode)) return;
      const container = findPasswordContainer(buttonNode);
      if (!container) return;
      stageFrom(container);
    },
    true,
  );
  document.addEventListener(
    "input",
    (event) => {
      if (!(event.target instanceof HTMLInputElement)) return;
      if (event.target.type !== "password") return;
      if (!loginInput(event.target)) return;
      const snapshot = extractCredentials(event.target);
      if (snapshot)
        lastEditedCredential = {
          ...snapshot,
          element: event.target,
          updatedAt: Date.now(),
        };
    },
    true,
  );
  function stageEditedCredential() {
    if (
      !lastEditedCredential ||
      Date.now() - lastEditedCredential.updatedAt > 15000
    ) {
      lastEditedCredential = null;
      return;
    }
    const { element: editedField, updatedAt, ...snapshot } =
      lastEditedCredential;
    stageSnapshot(snapshot);
  }
  window.addEventListener("popstate", stageEditedCredential);
  window.addEventListener("hashchange", stageEditedCredential);
  // Paste protection mirrors the reference extension's two paste guards while
  // keeping this extension's rule that a secret only ever reaches a page after
  // an explicit user decision. The pasted text is held in this closure only
  // until the choice is made and is never sent to the worker.
  function insertPastedText(field, text) {
    try {
      const start =
        typeof field.selectionStart === "number" ? field.selectionStart : null;
      const end =
        typeof field.selectionEnd === "number" ? field.selectionEnd : start;
      if (start !== null && typeof field.setRangeText === "function") {
        field.setRangeText(text, start, end, "end");
      } else if (nativeValue?.set) {
        nativeValue.set.call(field, inputValue(field) + text);
      } else {
        field.value = inputValue(field) + text;
      }
    } catch {
      return false;
    }
    try {
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
    } catch {}
    return true;
  }
  function showPasteWarning(field, text, kind) {
    const box = panel(field, "粘贴保护");
    note(
      box,
      kind === "secret-key"
        ? "这看起来是 Locklark 的 Secret Key。Secret Key 只应在 Locklark 应用中使用。"
        : "此网站没有已保存的登录。确认信任此网站后再粘贴密码。",
    );
    const cancel = button(box, "取消粘贴", () => dismiss());
    button(box, "仍要粘贴", () => {
      dismiss();
      // The original paste default action has already been cancelled, so a
      // failed insertion must be reported instead of silently dropping text.
      if (!insertPastedText(field, text)) {
        showToast("无法自动完成粘贴，请重新复制后手动粘贴");
        return;
      }
      try {
        field.focus();
      } catch {}
    });
    try {
      cancel.focus();
    } catch {}
  }
  function installPasteProtection() {
    document.addEventListener(
      "paste",
      (event) => {
        if (!event.isTrusted) return;
        if (siteSettings.pasteProtection === false) return;
        const field = eventInputTarget(event);
        const tag = String((field && field.tagName) || "").toUpperCase();
        if (tag !== "INPUT" && tag !== "TEXTAREA") return;
        if (field.disabled || field.readOnly) return;
        let text = "";
        try {
          text = String(event.clipboardData?.getData("text/plain") || "");
        } catch {
          return;
        }
        const password =
          tag === "INPUT" && String(field.type).toLowerCase() === "password";
        // Signup and confirm-password fields routinely receive a generated
        // password by paste; they are not a phishing signal.
        const currentPassword =
          password &&
          !isNewPasswordInput(field) &&
          !isConfirmPassword(field);
        const kind = core?.pasteWarning?.({
          text,
          enabled: siteSettings.pasteProtection !== false,
          isPasswordField: currentPassword,
          siteLinked: siteLinkedForPaste(),
        });
        if (!kind) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        showPasteWarning(field, text, kind);
      },
      true,
    );
  }
  installPasteProtection();
  if (typeof MutationObserver === "function") {
    const observer = new MutationObserver(() => {
      if (!lastEditedCredential) return;
      if (Date.now() - lastEditedCredential.updatedAt > 15000) {
        lastEditedCredential = null;
        return;
      }
      const editedField = lastEditedCredential.element;
      if (editedField?.isConnected && visibleField(editedField)) return;
      clearTimeout(mutationCheckTimer);
      mutationCheckTimer = setTimeout(stageEditedCredential, 50);
    });
    const startObserver = () => {
      if (!document.documentElement) return;
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["hidden", "style", "class", "aria-hidden"],
      });
    };
    if (document.documentElement) startObserver();
    else
      document.addEventListener("DOMContentLoaded", startObserver, {
        once: true,
      });
  }

  function dismissPending() {
    if (pendingHost) pendingHost.remove();
    pendingHost = null;
    pendingStageId = "";
  }
  function showToast(textValue) {
    if (toastHost) {
      toastHost.remove();
      toastHost = null;
    }
    clearTimeout(toastTimer);
    const toast = element("div");
    toast.style.cssText =
      "all:initial!important;position:fixed!important;right:16px!important;top:16px!important;z-index:2147483647!important;display:block!important;";
    const shadow = toast.attachShadow({ mode: "closed" });
    const style = element("style");
    style.textContent =
      ".toast{box-sizing:border-box;max-width:340px;padding:10px 14px;border-radius:8px;background:#163f36;color:#fff;font:13px system-ui;box-shadow:0 8px 30px #0004;overflow-wrap:anywhere}";
    const box = element("div", textValue, "toast");
    box.setAttribute("role", "status");
    shadow.append(style, box);
    document.documentElement.append(toast);
    toastHost = toast;
    toastTimer = setTimeout(() => {
      toast.remove();
      if (toastHost === toast) toastHost = null;
    }, 2400);
  }
  function showPendingSaveBanner(staged) {
    if (
      !staged ||
      typeof staged.stageId !== "string" ||
      !["new", "update"].includes(staged.mode)
    )
      return;
    if (pendingHost) pendingHost.remove();
    pendingHost = element("div");
    pendingStageId = staged.stageId;
    pendingHost.style.cssText =
      "all:initial!important;position:fixed!important;right:16px!important;top:16px!important;z-index:2147483647!important;display:block!important;";
    const shadow = pendingHost.attachShadow({ mode: "closed" });
    const style = element("style");
    style.textContent =
      ".banner{box-sizing:border-box;width:340px;max-width:calc(100vw - 32px);background:light-dark(#fff,#1f2430);color:light-dark(#192235,#f2f4f8);border:1px solid #798298;border-radius:12px;padding:12px;box-shadow:0 8px 30px #0004;font:13px system-ui}.banner strong{display:block;font-size:14px;margin-bottom:6px}.banner p{margin:4px 0;overflow-wrap:anywhere}.banner .mono{font-family:ui-monospace,monospace}.banner button{display:block;width:100%;text-align:left;font:inherit;padding:8px;margin-top:6px;border:0;border-radius:6px;background:light-dark(#e8efff,#2a3140);color:inherit;cursor:pointer}.banner button:hover,.banner button:focus{background:light-dark(#d7e5ff,#344667);outline:2px solid #8daef9}.banner button:disabled{opacity:.55;cursor:default}.banner input[type=text]{box-sizing:border-box;width:100%;margin-top:3px;font:inherit;padding:6px;border:1px solid #798298;border-radius:6px;background:light-dark(#fff,#1f2430);color:inherit}.status{font-size:12px;color:light-dark(#52645a,#b9c5d3)}";
    const box = element("section");
    box.className = "banner";
    box.setAttribute("role", "alertdialog");
    box.setAttribute("aria-label", "Locklark 保存登录");
    box.append(
      element(
        "strong",
        staged.mode === "update"
          ? "Locklark · 是否更新此登录密码？"
          : "Locklark · 是否保存此网站登录？",
      ),
    );
    box.append(element("p", staged.origin || location.origin));
    const titleLabel = element("label", "标题");
    const titleInput = element("input");
    titleInput.type = "text";
    titleInput.maxLength = 1024;
    titleInput.value =
      typeof staged.title === "string" && staged.title
        ? staged.title
        : location.hostname;
    titleLabel.append(titleInput);
    box.append(titleLabel);
    box.append(
      element(
        "p",
        "用户名：" + (staged.username || "（无用户名）"),
        "mono",
      ),
    );
    const status = element("p", "", "status");
    let busy = false;
    const controls = [];
    function setBusy(value) {
      busy = value;
      for (const control of controls) control.disabled = value;
    }
    async function commit(mode) {
      if (busy) return;
      setBusy(true);
      status.textContent = "";
      try {
        if (!staged.connected) {
          const connection = await send({ type: "inline-connect" });
          if (!connection?.connected) {
            status.textContent = "解锁未完成，请重试";
            return;
          }
        }
        const result = await send({
          type: "inline-commit-staged-save",
          stageId: staged.stageId,
          mode,
          itemId: staged.existingItemId,
          revision: staged.existingRevision,
          title: titleInput.value.trim() || location.hostname,
        });
        if (result?.saved) {
          dismissPending();
          // A confirmed save makes this origin linked for paste protection.
          siteLink = { origin: location.origin, linked: true, at: Date.now() };
          showToast("已保存到 Locklark");
        } else status.textContent = result?.status || "保存失败，请稍后重试";
      } catch {
        status.textContent = "保存失败，请稍后重试";
      } finally {
        setBusy(false);
      }
    }
    const label = !staged.connected
      ? "解锁 Locklark 并保存"
      : staged.mode === "update"
        ? "更新密码 · " + (staged.title || location.hostname)
        : "保存到 Locklark";
    controls.push(
      button(box, label, () =>
        commit(staged.mode === "update" ? "update" : "new"),
      ),
    );
    if (staged.mode === "update")
      controls.push(
        button(box, "另存为新登录", () => commit("new")),
      );
    controls.push(
      button(box, "暂不保存", async () => {
        if (busy) return;
        setBusy(true);
        try {
          await send({
            type: "inline-dismiss-save",
            stageId: staged.stageId,
            neverForOrigin: false,
          });
          dismissPending();
          showToast("已忽略本次保存");
        } catch {
          status.textContent = "操作失败，请稍后重试";
        } finally {
          setBusy(false);
        }
      }),
    );
    controls.push(
      button(box, "在此网站永不提示保存", async () => {
        if (busy) return;
        setBusy(true);
        try {
          await send({
            type: "inline-dismiss-save",
            stageId: staged.stageId,
            neverForOrigin: true,
          });
          dismissPending();
          showToast("已设置此网站不再提示保存");
        } catch {
          status.textContent = "操作失败，请稍后重试";
        } finally {
          setBusy(false);
        }
      }),
    );
    box.append(status);
    shadow.append(style, box);
    document.documentElement.append(pendingHost);
  }
  async function checkPendingSave() {
    if (pendingCheckInFlight || request) return;
    pendingCheckInFlight = true;
    try {
      const result = await send({ type: "inline-pending-save" });
      if (
        !result?.pendingSave ||
        !["new", "update"].includes(result.pendingSave.mode)
      ) {
        dismissPending();
        return;
      }
      if (
        pendingHost &&
        pendingStageId === result.pendingSave.stageId &&
        pendingHost.isConnected
      )
        return;
      showPendingSaveBanner(result.pendingSave);
    } catch {
    } finally {
      pendingCheckInFlight = false;
    }
  }

  // Reposition/revalidate the open panel without ever exposing page values.
  document.addEventListener("scroll", setPanelPosition, {
    capture: true,
    passive: true,
  });
  window.addEventListener("resize", setPanelPosition, { passive: true });
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
    dismissPending();
    if (request) void send({ type: "passkey-cancel", id: request.id });
    request = null;
    if (conditionalRequest)
      void send({ type: "passkey-cancel", id: conditionalRequest.id });
    clearConditional();
  });
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", () => void checkPendingSave(), {
      once: true,
    });
  else void checkPendingSave();
  setTimeout(() => void checkPendingSave(), 1200);

  function fillFields(fields) {
    if (!fields || typeof fields !== "object" || Array.isArray(fields))
      return 0;
    const inputs = [...document.querySelectorAll("input,textarea,select")];
    let filled = 0;
    for (const [key, value] of Object.entries(fields).slice(0, 100)) {
      if (typeof value !== "string" || value.length > 16384) continue;
      const normalized = key.toLowerCase().replace(/[_-]/g, "");
      const input = inputs.find((element) => {
        if (element.disabled || element.readOnly) return false;
        const autocomplete = (
          element.getAttribute?.("autocomplete") ||
          element.autocomplete ||
          ""
        )
          .toLowerCase()
          .replace(/[_-]/g, "");
        return (
          autocomplete === normalized ||
          String(element.name || "")
            .toLowerCase()
            .replace(/[_-]/g, "") === normalized ||
          String(element.id || "")
            .toLowerCase()
            .replace(/[_-]/g, "") === normalized
        );
      });
      if (!input) continue;
      const prototype =
        input instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : input instanceof HTMLSelectElement
            ? HTMLSelectElement.prototype
            : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      if (!setter) continue;
      setter.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      filled++;
    }
    return filled;
  }
  try {
    api.runtime.onMessage.addListener((message, sender, respond) => {
      if (!sender || sender.id !== api.runtime.id) return false;
      // The worker invalidates a waiting conditional intent with a bare id; the
      // UI must not outlive a lock, disconnect, navigation or eviction.
      if (message?.type === "locklark:conditional-passkey-cancel") {
        const call = conditionalRequest;
        if (
          typeof message.id !== "string" ||
          !/^[a-f0-9-]{36}$/.test(message.id) ||
          !call ||
          call.id !== message.id
        ) {
          respond({ cancelled: false });
          return true;
        }
        clearConditional();
        dismiss();
        if (pendingDismissedForPasskey) {
          pendingDismissedForPasskey = false;
          setTimeout(() => void checkPendingSave(), 0);
        }
        call.finish({ error: "NotAllowedError" });
        respond({ cancelled: true });
        return true;
      }
      if (message?.type === "locklark:open-inline-menu") {
        const active = document.activeElement;
        const input =
          loginInput(active) && !active.closest?.("[data-locklark-ignore]")
            ? active
            : document.querySelector(
                'input[type="password"],input[autocomplete="username"],input[type="email"]',
              );
        if (input) void showSuggestions(input);
        respond({ opened: !!input });
        return true;
      }
      if (message?.type === "locklark:fill-fields") {
        let filled = 0;
        try {
          filled = fillFields(message.fields);
        } catch {}
        respond({ filled });
        return true;
      }
      return false;
    });
  } catch {}
  window.addEventListener("message", async (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    const m = event.data;
    if (m?.source === "locklark-capability-v1") {
      if (
        typeof m.id !== "string" ||
        !/^[a-f0-9-]{36}$/.test(m.id) ||
        Object.keys(m).some((key) => key !== "source" && key !== "id")
      )
        return;
      void replyConditionalCapability(m.id);
      return;
    }
    if (window !== window.top) return;
    if (m?.source === "locklark-signal-v1") {
      // Same top-frame, same-origin, visible-document policy as the credential
      // bridge; a hint is never forwarded from a hidden page.
      if (document.visibilityState !== "visible") return;
      forwardSignalHint(m);
      return;
    }
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      m?.source !== "locklark-request-v1" ||
      typeof m.id !== "string" ||
      !/^[a-f0-9-]{36}$/.test(m.id)
    )
      return;
    const finish = (value) => {
      window.postMessage(
        { source: "locklark-result-v1", id: m.id, ...value },
        location.origin,
      );
      if (pendingDismissedForPasskey) {
        pendingDismissedForPasskey = false;
        setTimeout(() => void checkPendingSave(), 0);
      }
    };
    if (m.type === "cancel") {
      if (conditionalRequest?.id === m.id) {
        clearConditional();
        dismiss();
        try {
          void send({ type: "passkey-cancel", id: m.id });
        } catch {}
        if (pendingDismissedForPasskey) {
          pendingDismissedForPasskey = false;
          setTimeout(() => void checkPendingSave(), 0);
        }
        return;
      }
      if (request?.id === m.id) {
        void send({ type: "passkey-cancel", id: m.id });
        request = null;
        dismiss();
        if (pendingDismissedForPasskey) {
          pendingDismissedForPasskey = false;
          setTimeout(() => void checkPendingSave(), 0);
        }
      }
      return;
    }
    if (m.type === "get" && m.conditional === true) {
      if (
        typeof m.options !== "string" ||
        m.options.length > 32768 ||
        conditionalRequest ||
        request ||
        document.visibilityState !== "visible"
      ) {
        finish({ fallback: true });
        return;
      }
      // Register the pending conditional call but show no UI until the user
      // focuses a WebAuthn autocomplete field.
      const own = { id: m.id, options: m.options, finish };
      conditionalRequest = own;
      conditionalGeneration++;
      let state;
      try {
        state = await send({ type: "inline-state" });
      } catch {}
      if (conditionalRequest !== own) return;
      if (
        !state ||
        state.offerUsePasskeys === false ||
        state.passkeyConditionalSupported !== true
      ) {
        clearConditional();
        finish({ fallback: true });
        return;
      }
      const active = deepActiveElement();
      if (conditionalField(active)) void showConditionalAccounts(active);
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
    // A stale login-save banner must never sit above the Passkey controls and
    // absorb their click. Hide it for this flow; finish() restores it only if
    // the host still reports a pending save afterwards.
    if (pendingHost) {
      dismissPending();
      pendingDismissedForPasskey = true;
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
