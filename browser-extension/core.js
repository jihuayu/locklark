/* Shared pure policy and static isolated-world injection functions. */
globalThis.LocklarkCore = (() => {
  "use strict";
  function originFromURL(raw) {
    if (
      typeof raw !== "string" ||
      raw.length > 8192 ||
      /[\\\x00-\x20\x7f-\uffff]/u.test(raw)
    )
      throw Error("refused");
    const authority = /^https:\/\/([^/?#]+)/.exec(raw);
    if (!authority || authority[1].includes("@")) throw Error("refused");
    const port = authority[1].match(/:(.*)$/);
    if (port && (!/^[1-9][0-9]{0,4}$/.test(port[1]) || Number(port[1]) > 65535))
      throw Error("refused");
    const u = new URL(raw);
    if (u.protocol !== "https:" || u.username || u.password)
      throw Error("refused");
    const host = u.hostname,
      labels = host.split(".");
    if (
      labels.length < 2 ||
      host.length > 253 ||
      !labels.every(
        (l) =>
          l.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(l) &&
          !l.startsWith("xn--"),
      ) ||
      !/^[a-z]{2,}$/.test(labels.at(-1)) ||
      [".localhost", ".local", ".internal", ".home.arpa"].some((s) =>
        host.endsWith(s),
      )
    )
      throw Error("refused");
    return u.origin;
  }
  function validSender(sender, runtime) {
    return (
      !!sender &&
      sender.id === runtime.id &&
      sender.url === runtime.getURL("popup.html") &&
      !sender.tab
    );
  }
  function sameContext(a, b) {
    return (
      !!a &&
      !!b &&
      a.tabId === b.tabId &&
      a.windowId === b.windowId &&
      a.documentId === b.documentId &&
      a.origin === b.origin
    );
  }
  function validResponse(m) {
    if (
      !m ||
      typeof m !== "object" ||
      Array.isArray(m) ||
      m.v !== 1 ||
      typeof m.type !== "string"
    )
      return false;
    const shapes = {
        locked: ["v", "type"],
        unpaired: ["v", "type", "error"],
        paired: ["v", "id", "type", "capability"],
        candidates: ["v", "id", "type", "candidates"],
        fill: ["v", "id", "type", "username", "password"],
        error: ["v", "id", "type", "error"],
        cancelled: ["v", "id", "type"],
        "save-ready": ["v", "id", "type", "nonce"],
        saved: ["v", "id", "type", "item_id", "revision"],
        unknown: ["v", "id", "type"],
      },
      keys = shapes[m.type];
    if (!keys || Object.keys(m).some((k) => !keys.includes(k))) return false;
    if (m.type === "locked") return true;
    if (m.type === "unpaired") return m.error === "expired";
    if (!/^[a-f0-9]{32}$/.test(m.id || "")) return false;
    if (m.type === "save-ready") return /^[a-f0-9]{64}$/.test(m.nonce || "");
    if (m.type === "saved")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "")
      );
    if (m.type === "paired") return /^[a-f0-9]{32}$/.test(m.capability || "");
    if (m.type === "error") return m.error === "refused";
    if (m.type === "fill")
      return (
        typeof m.username === "string" &&
        typeof m.password === "string" &&
        m.username.length <= 16384 &&
        m.password.length <= 16384
      );
    if (m.type === "candidates")
      return (
        m.candidates === undefined ||
        (Array.isArray(m.candidates) &&
          m.candidates.length <= 100 &&
          m.candidates.every(
            (r) =>
              r &&
              typeof r === "object" &&
              !Array.isArray(r) &&
              Object.keys(r).every((k) =>
                ["id", "revision", "title", "state"].includes(k),
              ) &&
              /^[a-f0-9]{32}$/.test(r.id || "") &&
              /^[a-f0-9]{64}$/.test(r.revision || "") &&
              typeof r.title === "string" &&
              r.title.length <= 1024 &&
              r.state === "active",
          ))
      );
    return true;
  }
  // These functions are self-contained because scripting serializes the function.
  function probe() {
    return { origin: location.origin, top: window === window.top };
  }
  function fillDocument(expected, username, password, expiresAt, captureOnly) {
    "use strict";
    try {
      if (
        !Number.isSafeInteger(expiresAt) ||
        Date.now() >= expiresAt ||
        expiresAt - Date.now() > 2000 ||
        window !== window.top ||
        location.origin !== expected ||
        typeof username !== "string" ||
        typeof password !== "string" ||
        username.length > 16384 ||
        password.length > 16384
      )
        return false;
      function eligible(el) {
        if (
          !el ||
          !el.isConnected ||
          el.disabled ||
          el.readOnly ||
          el.matches(":disabled") ||
          el.closest('[hidden],[inert],[aria-hidden="true"]')
        )
          return false;
        for (let n = el; n instanceof Element; n = n.parentElement) {
          const s = getComputedStyle(n);
          if (
            s.display === "none" ||
            s.visibility !== "visible" ||
            Number(s.opacity) === 0
          )
            return false;
        }
        const r = el.getBoundingClientRect();
        return el.getClientRects().length > 0 && r.width > 0 && r.height > 0;
      }
      const passwords = [
        ...document.querySelectorAll('input[type="password"]'),
      ];
      const users = [...document.querySelectorAll("input")].filter(
        (e) => e.type === "text" || e.type === "email",
      );
      if (passwords.length !== 1 || users.length !== 1) return false;
      const pass = passwords[0],
        user = users[0],
        form = pass.form;
      if (
        !eligible(pass) ||
        !eligible(user) ||
        !form ||
        form !== user.form ||
        form.ownerDocument !== document
      )
        return false;
      function sameAction(raw) {
        const u = new URL(raw || location.href, document.baseURI);
        return (
          u.protocol === "https:" &&
          u.origin === expected &&
          !u.username &&
          !u.password
        );
      }
      if (!sameAction(form.getAttribute("action"))) return false;
      for (const el of document.querySelectorAll(
        "button[formaction],input[formaction]",
      ))
        if (el.form === form && !sameAction(el.getAttribute("formaction")))
          return false;
      const set = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      // No events or await between the final checks and both writes. Page handlers
      // cannot navigate synchronously after the first write and redirect the second.
      if (
        location.origin !== expected ||
        !eligible(user) ||
        !eligible(pass) ||
        user.form !== form ||
        pass.form !== form ||
        !sameAction(form.getAttribute("action")) ||
        Date.now() >= expiresAt
      )
        return false;
      if (captureOnly) {
        const get = Object.getOwnPropertyDescriptor(
          HTMLInputElement.prototype,
          "value",
        ).get;
        const username = get.call(user),
          password = get.call(pass);
        function valid(value) {
          for (let n = 0; n < value.length; n++) {
            const code = value.charCodeAt(n);
            if (code >= 0xdc00 && code <= 0xdfff) return false;
            if (code >= 0xd800 && code <= 0xdbff) {
              const low = value.charCodeAt(++n);
              if (!(low >= 0xdc00 && low <= 0xdfff)) return false;
            }
            if (
              (code < 32 && ![9, 10, 13].includes(code)) ||
              code === 0xfffe ||
              code === 0xffff
            )
              return false;
          }
          return new TextEncoder().encode(value).length <= 16384;
        }
        if (
          !valid(username) ||
          !valid(password) ||
          password.length === 0 ||
          Date.now() >= expiresAt
        )
          return false;
        return { username, password };
      }
      set.call(user, username);
      set.call(pass, password);
      user.dispatchEvent(new Event("input", { bubbles: true }));
      pass.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    } catch {
      return false;
    }
  }
  return {
    originFromURL,
    validSender,
    sameContext,
    validResponse,
    probe,
    fillDocument,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
