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
        "vault-items": ["v", "id", "type", "items"],
        "item-detail": ["v", "id", "type", "item"],
        generated: ["v", "id", "type", "password"],
        "fill-fields": ["v", "id", "type", "fields"],
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
    if (m.type === "vault-items")
      return (
        Array.isArray(m.items) &&
        m.items.length <= 500 &&
        m.items.every(
          (item) =>
            item &&
            typeof item === "object" &&
            !Array.isArray(item) &&
            typeof item.id === "string" &&
            /^[a-f0-9]{32}$/.test(item.id) &&
            typeof item.revision === "string" &&
            /^[a-f0-9]{64}$/.test(item.revision) &&
            typeof item.title === "string" &&
            item.title.length <= 1024 &&
            typeof item.category === "string" &&
            item.category.length <= 64,
        )
      );
    if (m.type === "item-detail")
      return (
        m.item &&
        typeof m.item === "object" &&
        !Array.isArray(m.item) &&
        typeof m.item.id === "string" &&
        /^[a-f0-9]{32}$/.test(m.item.id) &&
        typeof m.item.revision === "string" &&
        /^[a-f0-9]{64}$/.test(m.item.revision) &&
        typeof m.item.title === "string" &&
        m.item.title.length <= 1024 &&
        typeof m.item.category === "string" &&
        m.item.category.length <= 64
      );
    if (m.type === "generated")
      return (
        typeof m.password === "string" &&
        m.password.length > 0 &&
        m.password.length <= 1024
      );
    if (m.type === "fill-fields")
      return (
        m.fields &&
        typeof m.fields === "object" &&
        !Array.isArray(m.fields) &&
        Object.keys(m.fields).length <= 100 &&
        Object.entries(m.fields).every(
          ([key, value]) =>
            /^[A-Za-z0-9_.-]{1,128}$/.test(key) &&
            typeof value === "string" &&
            value.length <= 16384,
        )
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
  function fillGeneratedPasswordDocument(expected, password, expiresAt) {
    "use strict";
    try {
      if (
        !Number.isSafeInteger(expiresAt) ||
        Date.now() >= expiresAt ||
        expiresAt - Date.now() > 2000 ||
        window !== window.top ||
        location.origin !== expected ||
        typeof password !== "string" ||
        password.length === 0 ||
        password.length > 1024
      )
        return false;
      function eligible(el) {
        if (
          !el ||
          !el.isConnected ||
          el.disabled ||
          el.readOnly ||
          !["password", "text"].includes(el.type) ||
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
      const passwords = [...document.querySelectorAll('input[type="password"]')]
        .filter(eligible)
        .filter(
          (el) =>
            !((el.getAttribute && el.getAttribute("autocomplete")) || "")
              .toLowerCase()
              .split(/\s+/)
              .includes("current-password"),
        );
      const focused = passwords.filter((el) => el === document.activeElement);
      if (focused.length !== 1 && passwords.length !== 1) return false;
      const input = focused[0] || passwords[0];
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      if (Date.now() >= expiresAt) return false;
      setter.call(input, password);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    } catch {
      return false;
    }
  }
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
  const DEFAULT_SETTINGS = Object.freeze({
    sharedDesktopSession: true,
    allowBiometricUnlock: true,
    showToolbarBadgeCount: true,
    showInlineMenu: true,
    autoLogin: true,
    openAndFillAutoSubmit: true,
    offerFillIdentitiesAndCards: true,
    offerUsePasskeys: true,
    offerSaveLogins: true,
    offerSavePasskeys: true,
    showInlineGenerator: true,
    generatorDefaults: Object.freeze({
      mode: "random",
      length: 24,
      digits: true,
      symbols: true,
    }),
    loginOverrides: Object.freeze({}),
    disabledInlineMenuOrigins: Object.freeze([]),
    neverSaveOrigins: Object.freeze([]),
    clipboardClearSeconds: 30,
    watchtowerLocalChecks: true,
    theme: "system",
  });
  const ITEM_CATEGORIES = Object.freeze([
    "login",
    "password",
    "note",
    "identity",
    "card",
    "ssh",
  ]);
  const FILTER_CATEGORIES = Object.freeze([
    "all",
    "login",
    "password",
    "identity",
    "credit_card",
    "secure_note",
    "ssh",
    "favorites",
    "suggested",
  ]);
  const FIELD_TYPES = Object.freeze([
    "text",
    "concealed",
    "password",
    "url",
    "email",
    "date",
    "totp",
    "multiline",
    "cvv",
    "card_number",
  ]);
  function normalizeCategory(raw) {
    if (typeof raw !== "string") return "";
    const value = raw.trim().toLowerCase();
    if (value === "credit_card" || value === "credit-card" || value === "card")
      return "card";
    if (
      value === "secure_note" ||
      value === "secure-note" ||
      value === "note"
    )
      return "note";
    if (value === "ssh_key" || value === "ssh-key" || value === "ssh")
      return "ssh";
    return ITEM_CATEGORIES.includes(value) ? value : "";
  }
  function validCategory(raw) {
    return FILTER_CATEGORIES.includes(raw);
  }
  function normalizeGeneratorDefaults(raw) {
    const source =
      raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
    const mode = ["random", "memorable", "pin"].includes(source.mode)
      ? source.mode
      : DEFAULT_SETTINGS.generatorDefaults.mode;
    const low = mode === "pin" ? 4 : mode === "memorable" ? 3 : 8;
    const high = mode === "pin" ? 12 : mode === "memorable" ? 12 : 128;
    const requested = Number.isSafeInteger(source.length)
      ? source.length
      : DEFAULT_SETTINGS.generatorDefaults.length;
    return {
      mode,
      length: Math.max(low, Math.min(high, requested)),
      digits:
        typeof source.digits === "boolean"
          ? source.digits
          : DEFAULT_SETTINGS.generatorDefaults.digits,
      symbols:
        typeof source.symbols === "boolean"
          ? source.symbols
          : DEFAULT_SETTINGS.generatorDefaults.symbols,
    };
  }
  function normalizeOriginList(raw, limit = 100) {
    if (!Array.isArray(raw)) return [];
    const result = [];
    for (const value of raw.slice(0, limit)) {
      try {
        const origin = originFromURL(value);
        if (!result.includes(origin)) result.push(origin);
      } catch {}
    }
    return result;
  }
  function normalizeLoginOverrides(raw) {
    const result = {};
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return result;
    let count = 0;
    for (const [key, value] of Object.entries(raw)) {
      if (count >= 500) break;
      if (/^[a-f0-9]{32}$/.test(key) && typeof value === "boolean") {
        result[key] = value;
        count++;
      }
    }
    return result;
  }
  function normalizeSettings(raw) {
    const source =
      raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
    const result = {
      ...DEFAULT_SETTINGS,
      generatorDefaults: normalizeGeneratorDefaults(source.generatorDefaults),
      loginOverrides: normalizeLoginOverrides(source.loginOverrides),
      disabledInlineMenuOrigins: normalizeOriginList(
        source.disabledInlineMenuOrigins,
      ),
      neverSaveOrigins: normalizeOriginList(source.neverSaveOrigins),
    };
    for (const key of [
      "sharedDesktopSession",
      "allowBiometricUnlock",
      "showToolbarBadgeCount",
      "showInlineMenu",
      "autoLogin",
      "openAndFillAutoSubmit",
      "offerFillIdentitiesAndCards",
      "offerUsePasskeys",
      "offerSaveLogins",
      "offerSavePasskeys",
      "showInlineGenerator",
      "watchtowerLocalChecks",
    ])
      if (typeof source[key] === "boolean") result[key] = source[key];
    result.clipboardClearSeconds = Number.isSafeInteger(
      source.clipboardClearSeconds,
    )
      ? Math.max(5, Math.min(300, source.clipboardClearSeconds))
      : DEFAULT_SETTINGS.clipboardClearSeconds;
    result.theme = ["system", "light", "dark"].includes(source.theme)
      ? source.theme
      : DEFAULT_SETTINGS.theme;
    return result;
  }
  function itemOrigin(raw) {
    try {
      return originFromURL(raw);
    } catch {
      return "";
    }
  }
  function originHost(origin) {
    try {
      return new URL(origin).hostname;
    } catch {
      return "";
    }
  }
  function sameSite(a, b) {
    const left = originHost(a),
      right = originHost(b);
    if (!left || !right) return false;
    if (left === right) return true;
    const aLabels = left.split("."),
      bLabels = right.split(".");
    if (aLabels.length < 2 || bLabels.length < 2) return false;
    return (
      aLabels.slice(-2).join(".") === bLabels.slice(-2).join(".") &&
      !/^\d+$/.test(aLabels.at(-2))
    );
  }
  function itemMatchesOrigin(item, origin, siteWide = false) {
    if (!item || typeof item !== "object" || typeof origin !== "string")
      return false;
    let exact = false;
    for (const raw of Array.isArray(item.urls) ? item.urls.slice(0, 20) : []) {
      const candidate = itemOrigin(raw);
      if (!candidate) continue;
      if (candidate === origin) exact = true;
      else if (siteWide && sameSite(candidate, origin)) return true;
    }
    return exact;
  }
  function flattenItemFields(item) {
    if (!item || typeof item !== "object") return [];
    const result = [];
    const add = (field) => {
      if (!field || typeof field !== "object" || Array.isArray(field)) return;
      if (result.length >= 200) return;
      result.push({
        id: typeof field.id === "string" ? field.id.slice(0, 128) : "",
        label:
          typeof field.label === "string" ? field.label.slice(0, 256) : "",
        type: FIELD_TYPES.includes(field.type) ? field.type : "text",
        value: typeof field.value === "string" ? field.value.slice(0, 16384) : "",
        concealed: field.concealed === true,
      });
    };
    if (Array.isArray(item.fields)) item.fields.slice(0, 100).forEach(add);
    if (Array.isArray(item.sections))
      for (const section of item.sections.slice(0, 20))
        if (Array.isArray(section?.fields))
          section.fields.slice(0, 100).forEach(add);
    if (Array.isArray(item.custom_fields))
      item.custom_fields.slice(0, 100).forEach(add);
    return result;
  }
  function concealedType(type, concealed) {
    return (
      concealed === true ||
      ["concealed", "password", "cvv", "card_number"].includes(type)
    );
  }
  function formatFieldValue(field, revealed = false) {
    const value =
      field && typeof field === "object" && typeof field.value === "string"
        ? field.value
        : "";
    if (concealedType(field?.type, field?.concealed) && revealed !== true)
      return "••••••••••••";
    return value;
  }
  function itemSearchText(item) {
    if (!item || typeof item !== "object") return "";
    const parts = [
      item.title,
      item.subtitle,
      item.username,
      item.category,
      ...(Array.isArray(item.tags) ? item.tags : []),
      ...(Array.isArray(item.urls) ? item.urls : []),
      ...flattenItemFields(item).map((field) => field.label),
    ];
    return parts
      .filter((value) => typeof value === "string")
      .join(" ")
      .toLocaleLowerCase();
  }
  function filterVaultItems(items, options = {}) {
    if (!Array.isArray(items)) return [];
    const query =
      typeof options.query === "string"
        ? options.query.trim().slice(0, 500).toLocaleLowerCase()
        : "";
    const tokens = query.split(/\s+/).filter(Boolean);
    const category = validCategory(options.category) ? options.category : "all";
    const origin =
      typeof options.origin === "string" && options.origin
        ? itemOrigin(options.origin) || options.origin
        : "";
    const matches = [];
    for (const item of items.slice(0, 500)) {
      if (!item || typeof item !== "object") continue;
      const canonical = normalizeCategory(item.category) || "login";
      if (
        category !== "all" &&
        category !== "favorites" &&
        category !== "suggested" &&
        canonical !== normalizeCategory(category)
      )
        continue;
      if (category === "favorites" && item.favorite !== true) continue;
      if (
        category === "suggested" &&
        (!origin || !itemMatchesOrigin(item, origin, true))
      )
        continue;
      const haystack = itemSearchText(item);
      if (tokens.some((token) => !haystack.includes(token))) continue;
      matches.push(item);
    }
    return matches.sort((a, b) => {
      if (category === "suggested" && origin) {
        const ae = itemMatchesOrigin(a, origin, false) ? 1 : 0;
        const be = itemMatchesOrigin(b, origin, false) ? 1 : 0;
        if (ae !== be) return be - ae;
      }
      if ((a.favorite === true) !== (b.favorite === true))
        return a.favorite === true ? -1 : 1;
      return String(a.title || "").localeCompare(String(b.title || ""), "zh-CN");
    });
  }
  function validItemForSave(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return false;
    const category = normalizeCategory(item.category);
    if (!ITEM_CATEGORIES.includes(category)) return false;
    if (
      typeof item.title !== "string" ||
      item.title.length === 0 ||
      item.title.length > 1024
    )
      return false;
    if (item.favorite !== undefined && typeof item.favorite !== "boolean")
      return false;
    if (item.notes !== undefined) {
      if (typeof item.notes !== "string" || item.notes.length > 65536)
        return false;
    }
    if (item.urls !== undefined) {
      if (
        !Array.isArray(item.urls) ||
        item.urls.length > 20 ||
        item.urls.some((url) => {
          try {
            originFromURL(url);
            return false;
          } catch {
            return true;
          }
        })
      )
        return false;
    }
    if (item.tags !== undefined) {
      if (
        !Array.isArray(item.tags) ||
        item.tags.length > 50 ||
        item.tags.some(
          (tag) => typeof tag !== "string" || tag.length > 128,
        )
      )
        return false;
    }
    for (const key of [
      "username",
      "password",
      "otp_secret",
      "content",
      "first_name",
      "last_name",
      "email",
      "phone",
      "organization",
      "address1",
      "address2",
      "city",
      "state",
      "postal_code",
      "country",
      "cardholder",
      "brand",
      "card_number",
      "expiry",
      "cvv",
      "billing_postal_code",
    ])
      if (
        item[key] !== undefined &&
        (typeof item[key] !== "string" || item[key].length > 16384)
      )
        return false;
    if (item.fields !== undefined) {
      if (!Array.isArray(item.fields) || item.fields.length > 100) return false;
      for (const field of item.fields) {
        if (!field || typeof field !== "object" || Array.isArray(field))
          return false;
        if (
          typeof field.label !== "string" ||
          field.label.length === 0 ||
          field.label.length > 256 ||
          !FIELD_TYPES.includes(field.type) ||
          typeof field.value !== "string" ||
          field.value.length > 16384
        )
          return false;
      }
    }
    return true;
  }
  function itemURLAllowed(item, raw) {
    const origin = itemOrigin(raw);
    return !!origin && itemMatchesOrigin(item, origin, false);
  }
  const WORDS = Object.freeze(
    "amber anchor apple arrow badge basket beacon birch blaze bloom bolder breeze bridge bronze brook cedar charter cider cipher clover comet copper coral cosmos crimson crystal dawn delta drift ember falcon fern field finch flint forest forge frost galaxy garden glacier granite grove harbor haven hazel heron horizon island ivory jade jasper jungle kettle lagoon lantern lark lava lemon lily lunar maple marble meadow meteor mint mirror mist moss nectar noble north ocean olive onyx opal orbit orchid osprey pearl pebble pine planet plum polar prairie quartz quill rain raven reef ridge river robin rock rose ruby sail sand sapphire shadow shell shore silver sky slate snow solar spark spruce star steel stone storm summit sunset surf thyme thunder tide timber topaz trail tulip tundra valley velvet violet wave willow wind winter wolf zephyr".split(
      " ",
    ),
  );
  function secureRandom() {
    const source = globalThis.crypto;
    if (!source || typeof source.getRandomValues !== "function")
      throw Error("refused");
    const values = new Uint32Array(1);
    source.getRandomValues(values);
    return values[0] / 4294967296;
  }
  function generatePassword(options = {}, random = secureRandom) {
    const generator = normalizeGeneratorDefaults(options);
    const next = (max) => {
      const value = Number(random());
      if (!Number.isFinite(value) || value < 0 || value >= 1)
        throw Error("refused");
      return Math.floor(value * max);
    };
    if (generator.mode === "pin") {
      let result = "";
      for (let i = 0; i < generator.length; i++) result += next(10);
      return result;
    }
    if (generator.mode === "memorable") {
      const words = [];
      for (let i = 0; i < generator.length; i++)
        words.push(WORDS[next(WORDS.length)]);
      return words.join("-");
    }
    let alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    if (generator.digits) alphabet += "23456789";
    if (generator.symbols) alphabet += "!@#$%^&*()-_=+[]{}";
    const required = [];
    required.push("abcdefghijkmnopqrstuvwxyz"[next(25)]);
    required.push("ABCDEFGHJKLMNPQRSTUVWXYZ"[next(24)]);
    if (generator.digits) required.push("23456789"[next(8)]);
    if (generator.symbols) required.push("!@#$%^&*()-_=+[]{}"[next(20)]);
    while (required.length < generator.length)
      required.push(alphabet[next(alphabet.length)]);
    for (let i = required.length - 1; i > 0; i--) {
      const j = next(i + 1);
      [required[i], required[j]] = [required[j], required[i]];
    }
    return required.slice(0, generator.length).join("");
  }
  return {
    originFromURL,
    validSender,
    sameContext,
    validResponse,
    probe,
    fillDocument,
    fillGeneratedPasswordDocument,
    otpDocument,
    DEFAULT_SETTINGS,
    ITEM_CATEGORIES,
    FILTER_CATEGORIES,
    FIELD_TYPES,
    normalizeCategory,
    validCategory,
    normalizeGeneratorDefaults,
    normalizeOriginList,
    normalizeLoginOverrides,
    normalizeSettings,
    sameSite,
    itemMatchesOrigin,
    flattenItemFields,
    concealedType,
    formatFieldValue,
    itemSearchText,
    filterVaultItems,
    validItemForSave,
    itemURLAllowed,
    generatePassword,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
