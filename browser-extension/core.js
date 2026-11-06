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
        "passkey-result": ["v", "id", "type", "credential"],
        locked: ["v", "type"],
        unpaired: ["v", "type", "error"],
        paired: ["v", "id", "type", "capability", "quick_fill"],
        candidates: ["v", "id", "type", "candidates"],
        fill: ["v", "id", "type", "username", "password"],
        error: ["v", "id", "type", "error"],
        cancelled: ["v", "id", "type"],
        "save-ready": ["v", "id", "type", "nonce"],
        "otp-ready": ["v", "id", "type", "nonce"],
        "otp-fill": ["v", "id", "type", "code"],
        saved: ["v", "id", "type", "item_id", "revision"],
        unknown: ["v", "id", "type"],
      },
      keys = shapes[m.type];
    if (!keys || Object.keys(m).some((k) => !keys.includes(k))) return false;
    if (m.type === "locked") return true;
    if (m.type === "unpaired") return m.error === "expired";
    if (!/^[a-f0-9]{32}$/.test(m.id || "")) return false;
    if (m.type === "passkey-result")
      return typeof m.credential === "string" && m.credential.length <= 32768;
    if (m.type === "save-ready" || m.type === "otp-ready")
      return /^[a-f0-9]{64}$/.test(m.nonce || "");
    if (m.type === "otp-fill")
      return (
        typeof m.code === "string" && /^(?:[0-9]{6}|[0-9]{8})$/.test(m.code)
      );
    if (m.type === "saved")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "")
      );
    if (m.type === "paired")
      return (
        /^[a-f0-9]{32}$/.test(m.capability || "") &&
        (m.quick_fill === undefined || typeof m.quick_fill === "boolean")
      );
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
  function fillDocument(
    expected,
    username,
    password,
    expiresAt,
    captureOnly,
    autoLogin,
  ) {
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
      const allInputs = [...document.querySelectorAll("input")];
      const visible = allInputs.filter(eligible);
      if (
        captureOnly &&
        (allInputs.filter((e) => e.type === "password").length !== 1 ||
          allInputs.filter((e) => ["text", "email"].includes(e.type)).length !==
            1)
      )
        return false;
      const passwords = visible.filter((e) => e.type === "password");
      // Never select a password from a signup/reset form or guess between forms.
      if (
        passwords.length > 1 ||
        passwords.some((e) =>
          hasAutocomplete(e, "new-password"),
        )
      )
        return false;
      let pass = passwords[0] || null;
      let users = visible.filter(
        (e) =>
          ["text", "email"].includes(e.type) && (!pass || e.form === pass.form),
      );
      const semantic = users.filter(
        (e) =>
          hasAutocomplete(e, "username") ||
          e.type === "email" ||
          /^(user(name)?|login|email)$/i.test(e.name || e.id),
      );
      if (semantic.length === 1) users = semantic;
      if (users.length > 1) return false;
      const user = users[0] || null,
        form = (pass || user)?.form;
      if (
        !form ||
        form.ownerDocument !== document ||
        (pass && user && pass.form !== user.form)
      )
        return false;
      // Username-first flows must identify their field; a random text/search box
      // is not a login. Capture still needs an actual password.
      if (
        !pass &&
        (!user ||
          semantic.length !== 1 ||
          captureOnly ||
          allInputs.some((e) => e.type === "password"))
      )
        return false;
      if (
        pass &&
        !user &&
        allInputs.some(
          (e) => ["text", "email"].includes(e.type) && e.form === form,
        )
      )
        return false;
      if (pass && !user && captureOnly) return false;
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
        (user && (!eligible(user) || user.form !== form)) ||
        (pass && (!eligible(pass) || pass.form !== form)) ||
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
      if (user) set.call(user, username);
      if (pass) set.call(pass, password);
      for (const field of [user, pass].filter(Boolean)) {
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }
      if (
        autoLogin === true &&
        pass &&
        user &&
        form.method.toLowerCase() === "post" &&
        hasAutocomplete(pass, "current-password")
      ) {
        const submitters = [...form.elements].filter(
          (e) =>
            (e instanceof HTMLButtonElement || e instanceof HTMLInputElement) &&
            e.type === "submit" &&
            eligible(e),
        );
        // Page event handlers can replace fields or change formAction. Recheck
        // after all input/change handlers; never invoke arbitrary button clicks.
        const button = submitters.length === 1 ? submitters[0] : null;
        if (
          button &&
          form.isConnected &&
          eligible(user) &&
          eligible(pass) &&
          user.form === form &&
          pass.form === form &&
          location.origin === expected &&
          Date.now() < expiresAt &&
          sameAction(form.getAttribute("action")) &&
          sameAction(
            button.getAttribute("formaction") || form.getAttribute("action"),
          ) &&
          !/register|sign.?up|reset|change|delete|purchase|pay/i.test(
            button.textContent +
              " " +
              button.value +
              " " +
              form.getAttribute("action"),
          )
        ) {
          HTMLFormElement.prototype.requestSubmit.call(form, button);
        }
      }
      return true;
    } catch {
      return false;
    }
  }
  // Serialized into the original top-frame isolated world. Probe and fill use
  // one policy; no selector, page bridge, or input values leave the probe.
  function otpDocument(expected, mode, code, timing) {
    "use strict";
    try {
      if (
        window !== window.top ||
        location.origin !== expected ||
        !["probe", "fill"].includes(mode)
      )
        return false;
      function clock() {
        return {
          timeOrigin: performance.timeOrigin,
          now: performance.now(),
          wall: Date.now(),
        };
      }
      function alive(sample) {
        return (
          Number.isFinite(sample.timeOrigin) &&
          sample.timeOrigin > 0 &&
          Number.isFinite(sample.now) &&
          sample.now >= 0 &&
          Number.isSafeInteger(sample.wall) &&
          sample.wall > 0
        );
      }
      function inBudget() {
        const current = clock();
        return (
          alive(current) &&
          current.timeOrigin === timing.timeOrigin &&
          current.now >= timing.now &&
          current.now < timing.now + 1500 &&
          current.wall >= timing.wall &&
          current.wall < timing.wall + 1500
        );
      }
      if (mode === "probe") {
        if (code !== undefined || timing !== undefined) return false;
      } else if (
        typeof code !== "string" ||
        !/^(?:[0-9]{6}|[0-9]{8})$/.test(code) ||
        !timing ||
        typeof timing !== "object" ||
        Array.isArray(timing) ||
        Object.keys(timing).sort().join(",") !==
          "now,origin,timeOrigin,top,wall" ||
        timing.top !== true ||
        timing.origin !== expected ||
        !alive(timing) ||
        !inBudget()
      )
        return false;
      function eligible(input) {
        if (
          !input ||
          !input.isConnected ||
          input.disabled ||
          input.readOnly ||
          !["text", "tel", "number", "password"].includes(input.type) ||
          input.matches(":disabled") ||
          input.closest('[hidden],[inert],[aria-hidden="true"]') ||
          (input.maxLength >= 0 &&
            input.maxLength < (mode === "fill" ? code.length : 6))
        )
          return false;
        for (
          let node = input;
          node instanceof Element;
          node = node.parentElement
        ) {
          const style = getComputedStyle(node);
          if (
            style.display === "none" ||
            style.visibility !== "visible" ||
            Number(style.opacity) === 0
          )
            return false;
        }
        const rect = input.getBoundingClientRect();
        return (
          input.getClientRects().length > 0 && rect.width > 0 && rect.height > 0
        );
      }
      const inputs = [
        ...document.querySelectorAll('input[autocomplete="one-time-code"]'),
      ];
      if (inputs.length !== 1) return false;
      const input = inputs[0],
        form = input.form;
      function sameAction(raw) {
        const url = new URL(raw || location.href, document.baseURI);
        return (
          url.protocol === "https:" &&
          url.origin === expected &&
          !url.username &&
          !url.password
        );
      }
      function validTarget() {
        if (
          window !== window.top ||
          location.origin !== expected ||
          !eligible(input) ||
          !form ||
          input.form !== form ||
          !form.isConnected ||
          form.ownerDocument !== document ||
          !sameAction(form.getAttribute("action")) ||
          document.querySelectorAll('input[autocomplete="one-time-code"]')
            .length !== 1
        )
          return false;
        for (const submitter of document.querySelectorAll(
          "button[formaction],input[formaction]",
        ))
          if (
            submitter.form === form &&
            !sameAction(submitter.getAttribute("formaction"))
          )
            return false;
        return true;
      }
      if (!validTarget()) return false;
      if (mode === "probe") {
        const sample = clock();
        return alive(sample)
          ? { origin: expected, top: true, ...sample }
          : false;
      }
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      // No event or await separates the final checks and this sole write.
      if (!validTarget() || !inBudget()) return false;
      setter.call(input, code);
      code = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
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
    otpDocument,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
