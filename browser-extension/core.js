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
  function validStagedSave(v) {
    if (!v || typeof v !== "object" || Array.isArray(v)) return false;
    if (
      Object.keys(v).some(
        (k) =>
          ![
            "stage_id",
            "origin",
            "username",
            "title",
            "mode",
            "existing_item_id",
            "existing_revision",
            "expires_at",
          ].includes(k),
      )
    )
      return false;
    if (!/^[a-f0-9]{32}$/.test(v.stage_id || "")) return false;
    try {
      if (originFromURL(v.origin) !== v.origin) return false;
    } catch {
      return false;
    }
    if (
      typeof v.username !== "string" ||
      v.username.length > 16384 ||
      typeof v.title !== "string" ||
      v.title.length > 1024 ||
      !["new", "update", "unchanged", "never"].includes(v.mode) ||
      !Number.isSafeInteger(v.expires_at) ||
      v.expires_at < 0
    )
      return false;
    if (
      (v.existing_item_id || "") !== "" &&
      !/^[a-f0-9]{32}$/.test(v.existing_item_id)
    )
      return false;
    if (
      (v.existing_revision || "") !== "" &&
      !/^[a-f0-9]{64}$/.test(v.existing_revision)
    )
      return false;
    return true;
  }
  function validGeneratedProfile(p) {
    return (
      !!p &&
      typeof p === "object" &&
      !Array.isArray(p) &&
      Object.keys(p).sort().join(",") ===
        "alphabet_size,entropy_bits_floor,length,mode" &&
      ["random", "memorable", "pin"].includes(p.mode) &&
      Number.isSafeInteger(p.length) &&
      p.length >= 1 &&
      p.length <= 256 &&
      Number.isSafeInteger(p.alphabet_size) &&
      p.alphabet_size >= 2 &&
      p.alphabet_size <= 1000000 &&
      Number.isSafeInteger(p.entropy_bits_floor) &&
      p.entropy_bits_floor >= 0
    );
  }
  function validOriginList(list) {
    return (
      Array.isArray(list) &&
      list.length <= 256 &&
      list.every((origin) => {
        try {
          return originFromURL(origin) === origin;
        } catch {
          return false;
        }
      })
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
        paired: ["v", "id", "type", "capability", "quick_fill", "capabilities"],
        candidates: ["v", "id", "type", "candidates"],
        fill: ["v", "id", "type", "username", "password"],
        error: ["v", "id", "type", "error"],
        cancelled: ["v", "id", "type"],
        "save-ready": ["v", "id", "type", "nonce"],
        "otp-ready": ["v", "id", "type", "nonce"],
        "otp-fill": ["v", "id", "type", "code"],
        saved: ["v", "id", "type", "item_id", "revision"],
        unknown: ["v", "id", "type"],
        generated: [
          "v",
          "id",
          "type",
          "generated_password",
          "profile",
          "history_id",
        ],
        "save-staged": ["v", "id", "type", "staged_save"],
        "save-pending": ["v", "id", "type", "staged_save"],
        "save-dismissed": ["v", "id", "type", "never_origins"],
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
        (m.quick_fill === undefined || typeof m.quick_fill === "boolean") &&
        (m.capabilities === undefined ||
          (Array.isArray(m.capabilities) &&
            m.capabilities.length <= 32 &&
            m.capabilities.every(
              (c) =>
                typeof c === "string" &&
                c.length >= 1 &&
                c.length <= 64 &&
                /^[a-z0-9-]+$/.test(c),
            )))
      );
    if (m.type === "generated")
      return (
        typeof m.generated_password === "string" &&
        m.generated_password.length >= 4 &&
        m.generated_password.length <= 256 &&
        m.generated_password.isWellFormed() &&
        validGeneratedProfile(m.profile) &&
        (m.history_id === undefined || /^[a-f0-9]{32}$/.test(m.history_id))
      );
    if (m.type === "save-staged")
      return validStagedSave(m.staged_save);
    if (m.type === "save-pending")
      return m.staged_save === undefined || validStagedSave(m.staged_save);
    if (m.type === "save-dismissed")
      return m.never_origins === undefined || validOriginList(m.never_origins);
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
  // A small curated English word list for memorable passwords. It is intentionally
  // flat, lowercase and free of ambiguous or offensive terms.
  const WORDS = (
    "able acid aged also area army away baby back ball band bank base bath bear beat " +
    "been beer bell belt best bill bird blue boat body bone book boot born both bowl " +
    "bulk burn bush busy cake call calm came camp card care case cash cast cell chat " +
    "chip city club coal coat code cold come cook cool cope copy core cost crew crop " +
    "dark data date dawn days dead deal dean dear debt deep deer desk dial diet disc " +
    "disk does done door dose down draw drew drop drug dual duke dust duty each earn " +
    "ease east easy edge else even ever face fact fail fair fall farm fast fear feed " +
    "feel feet fell felt file fill film find fine fire firm fish five flat flow food " +
    "foot ford form fort four free from fuel full fund gain game gate gave gear gene " +
    "gift girl give glad goal goes gold golf gone good gray grew grow gulf hair half " +
    "hall hand hang hard harm hate have head hear heat held hell help here hero high " +
    "hill hire hold hole holy home hope host hour huge hung hunt hurt idea inch into " +
    "iron item join jump jury just keen keep kept kick kind king knee knew know lack " +
    "lady lake land lane last late lead leaf lean left less life lift like line link " +
    "list live load loan lock long look loss lost love luck made mail main make male " +
    "many mark mass meal mean meat meet menu mere mile milk mill mind mine miss mode"
  ).split(" ");
  const RANDOM_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const RANDOM_LOWER = "abcdefghijklmnopqrstuvwxyz";
  const RANDOM_DIGITS = "0123456789";
  const RANDOM_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const MEMORABLE_SEPARATORS = {
    hyphens: () => "-",
    spaces: () => " ",
    periods: () => ".",
    commas: () => ",",
    underscores: () => "_",
    numbers: () => RANDOM_DIGITS[randomInt(RANDOM_DIGITS.length)],
    "numbers-and-symbols": () =>
      (RANDOM_DIGITS + RANDOM_SYMBOLS)[
        randomInt(RANDOM_DIGITS.length + RANDOM_SYMBOLS.length)
      ],
  };
  function randomInt(bound) {
    if (!Number.isSafeInteger(bound) || bound < 1 || bound > 256)
      throw Error("refused");
    if (
      !globalThis.crypto ||
      typeof globalThis.crypto.getRandomValues !== "function"
    )
      throw Error("refused");
    const limit = 256 - (256 % bound),
      byte = new Uint8Array(1);
    for (let attempt = 0; attempt < 128; attempt++) {
      globalThis.crypto.getRandomValues(byte);
      if (byte[0] < limit) return byte[0] % bound;
    }
    throw Error("refused");
  }
  function shuffled(values) {
    for (let i = values.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      const value = values[i];
      values[i] = values[j];
      values[j] = value;
    }
    return values;
  }
  function entropyFloor(alphabetSize, length) {
    if (!(alphabetSize > 1) || !(length > 0)) return 0;
    return Math.floor(length * Math.log2(alphabetSize));
  }
  function integerOption(value, min, max, fallback) {
    return Number.isSafeInteger(value)
      ? Math.min(max, Math.max(min, value))
      : fallback;
  }
  function booleanOption(value, fallback) {
    return typeof value === "boolean" ? value : fallback;
  }
  // Pure CSPRNG generator. It never returns a value produced by Math.random and
  // uses unbiased rejection sampling for every character and word choice.
  function generatePassword(options = {}) {
    if (
      !options ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      Object.keys(options).some(
        (k) =>
          ![
            "mode",
            "length",
            "digits",
            "symbols",
            "separator",
            "capitalize",
          ].includes(k),
      )
    )
      throw Error("refused");
    const mode = ["random", "memorable", "pin"].includes(options.mode)
      ? options.mode
      : "random";
    if (mode === "random") {
      const length = integerOption(options.length, 8, 256, 24);
      const digits = booleanOption(options.digits, true);
      const symbols = booleanOption(options.symbols, true);
      const classes = [RANDOM_UPPER, RANDOM_LOWER];
      if (digits) classes.push(RANDOM_DIGITS);
      if (symbols) classes.push(RANDOM_SYMBOLS);
      const alphabet = classes.join(""),
        output = [];
      for (const value of classes)
        output.push(value[randomInt(value.length)]);
      while (output.length < length)
        output.push(alphabet[randomInt(alphabet.length)]);
      shuffled(output);
      return {
        password: output.join(""),
        profile: {
          mode,
          length,
          alphabet_size: alphabet.length,
          entropy_bits_floor: entropyFloor(alphabet.length, length),
        },
      };
    }
    if (mode === "memorable") {
      const length = integerOption(options.length, 3, 10, 4);
      const separator = Object.hasOwn(
        MEMORABLE_SEPARATORS,
        options.separator,
      )
        ? options.separator
        : "hyphens";
      const capitalize = booleanOption(options.capitalize, true);
      const digits = booleanOption(options.digits, false);
      const words = [];
      for (let i = 0; i < length; i++) {
        let word = WORDS[randomInt(WORDS.length)];
        if (capitalize) word = word[0].toUpperCase() + word.slice(1);
        words.push(word);
      }
      const separatorIsNumeric =
        separator === "numbers" || separator === "numbers-and-symbols";
      if (digits && !separatorIsNumeric) {
        const index = randomInt(words.length);
        words[index] += String(10 + randomInt(90));
      }
      const output = [words[0]];
      for (let i = 1; i < words.length; i++)
        output.push(MEMORABLE_SEPARATORS[separator](), words[i]);
      return {
        password: output.join(""),
        profile: {
          mode,
          length,
          alphabet_size: WORDS.length,
          entropy_bits_floor: entropyFloor(WORDS.length, length),
        },
      };
    }
    const length = integerOption(options.length, 4, 12, 6),
      output = [];
    for (let i = 0; i < length; i++)
      output.push(RANDOM_DIGITS[randomInt(RANDOM_DIGITS.length)]);
    return {
      password: output.join(""),
      profile: {
        mode: "pin",
        length,
        alphabet_size: RANDOM_DIGITS.length,
        entropy_bits_floor: entropyFloor(RANDOM_DIGITS.length, length),
      },
    };
  }
  function passwordAutocomplete(el) {
    return (
      (el.getAttribute && el.getAttribute("autocomplete")) ||
      el.autocomplete ||
      ""
    )
      .toLowerCase()
      .split(/\s+/);
  }
  function passwordLabel(el) {
    return [el.name, el.id, el.placeholder, el.getAttribute?.("aria-label")]
      .filter((v) => typeof v === "string")
      .join(" ")
      .toLowerCase();
  }
  function looksCurrentPassword(el) {
    return (
      passwordAutocomplete(el).includes("current-password") ||
      /current|old|existing/i.test(passwordLabel(el))
    );
  }
  function looksConfirmPassword(el) {
    return /confirm|repeat|verify|again|retype/i.test(passwordLabel(el));
  }
  function looksNewPassword(el, action = "") {
    return (
      passwordAutocomplete(el).includes("new-password") ||
      /new.?pass|create.?pass|confirm.?pass|repeat.?pass|sign.?up|register|reset.?pass|change.?pass/i.test(
        passwordLabel(el) + " " + action,
      )
    );
  }
  // Pure role classification for one, two or three password inputs. It does not
  // read values and is used by both the content script and the fill/capture
  // routines selected during native-approved operations.
  function classifyPasswordFields(fields) {
    if (!Array.isArray(fields) || fields.length < 1 || fields.length > 3)
      return null;
    const [first, second, third] = fields;
    if (fields.length === 3)
      return {
        current: 0,
        new: 1,
        confirm: 2,
        isNewPassword: true,
        isPasswordChange: true,
        mode: "change",
      };
    if (fields.length === 2) {
      if (looksCurrentPassword(first) && !looksConfirmPassword(second))
        return {
          current: 0,
          new: 1,
          confirm: null,
          isNewPassword: true,
          isPasswordChange: true,
          mode: "change",
        };
      return {
        current: null,
        new: 0,
        confirm: 1,
        isNewPassword: true,
        isPasswordChange: false,
        mode: "signup",
      };
    }
    return {
      current: looksNewPassword(first) ? null : 0,
      new: looksNewPassword(first) ? 0 : null,
      confirm: null,
      isNewPassword: looksNewPassword(first),
      isPasswordChange: false,
      mode: looksNewPassword(first) ? "signup" : "login",
    };
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
          el.matches("[data-1p-ignore],[data-locklark-ignore]") ||
          el.closest(
            '[hidden],[inert],[aria-hidden="true"],[data-1p-ignore],[data-locklark-ignore]',
          )
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
      function label(el) {
        return [el.name, el.id, el.placeholder, el.getAttribute?.("aria-label")]
          .filter((value) => typeof value === "string")
          .join(" ")
          .toLowerCase();
      }
      function isCurrent(el) {
        return (
          hasAutocomplete(el, "current-password") ||
          /current|old|existing/i.test(label(el))
        );
      }
      function isConfirm(el) {
        return /confirm|repeat|verify|again|retype/i.test(label(el));
      }
      function isNew(el) {
        return (
          hasAutocomplete(el, "new-password") ||
          /new.?pass|create.?pass|confirm.?pass|repeat.?pass|sign.?up|register|reset.?pass|change.?pass/i.test(
            label(el) + " " + (el.form?.getAttribute("action") || ""),
          )
        );
      }
      const allInputs = [...document.querySelectorAll("input")];
      const visible = allInputs.filter(eligible);
      const passwords = visible.filter((e) => e.type === "password");
      // Native login fill only accepts a single current-password field. Save
      // capture additionally understands signup and change-password forms.
      if (
        captureOnly
          ? passwords.length < 1 || passwords.length > 3
          : passwords.length > 1 ||
            passwords.some((e) => hasAutocomplete(e, "new-password"))
      )
        return false;
      let currentPass = null,
        newPass = null,
        confirmPass = null;
      if (captureOnly) {
        if (passwords.length === 3) {
          currentPass = passwords[0];
          newPass = passwords[1];
          confirmPass = passwords[2];
        } else if (passwords.length === 2) {
          if (isCurrent(passwords[0]) && !isConfirm(passwords[1])) {
            currentPass = passwords[0];
            newPass = passwords[1];
          } else {
            newPass = passwords[0];
            confirmPass = passwords[1];
          }
        } else if (isNew(passwords[0])) {
          newPass = passwords[0];
        } else {
          currentPass = passwords[0];
        }
      }
      const pass = captureOnly
        ? newPass || currentPass
        : passwords[0] || null;
      const scopeForm = (pass || passwords[0])?.form;
      if (captureOnly && !scopeForm) return false;
      let users = visible.filter(
        (e) =>
          ["text", "email"].includes(e.type) &&
          (!scopeForm || e.form === scopeForm),
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
        form = scopeForm || user?.form;
      if (
        !form ||
        form.ownerDocument !== document ||
        (pass && user && pass.form !== form) ||
        (captureOnly && passwords.some((e) => e.form !== form))
      )
        return false;
      // Username-first flows must identify their field; a random text/search box
      // is not a login.
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
      const isNewPassword = !!newPass || (!!currentPass && isNew(currentPass));
      const isPasswordChange = !!currentPass && !!newPass;
      if (captureOnly && !user && !isNewPassword && !isPasswordChange)
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
      const getter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).get;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      // No events or await between the final checks and both writes. Page handlers
      // cannot navigate synchronously after the first write and redirect the second.
      if (
        location.origin !== expected ||
        (user && (!eligible(user) || user.form !== form)) ||
        (pass && (!eligible(pass) || pass.form !== form)) ||
        (captureOnly &&
          [currentPass, newPass, confirmPass]
            .filter(Boolean)
            .some((el) => !eligible(el) || el.form !== form)) ||
        !sameAction(form.getAttribute("action")) ||
        Date.now() >= expiresAt
      )
        return false;
      if (captureOnly) {
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
        const capturedUsername = user ? getter.call(user) : "";
        const capturedPassword = getter.call(pass);
        if (
          !valid(capturedUsername) ||
          !valid(capturedPassword) ||
          capturedPassword.length === 0 ||
          Date.now() >= expiresAt
        )
          return false;
        if (
          confirmPass &&
          getter.call(confirmPass) !== "" &&
          getter.call(confirmPass) !== capturedPassword
        )
          return false;
        return {
          username: capturedUsername,
          password: capturedPassword,
          isNewPassword,
          isPasswordChange,
        };
      }
      if (user) setter.call(user, username);
      if (pass) setter.call(pass, password);
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
  // Fill a generated password into the new-password field and its confirmation
  // field. A current-password field is never overwritten.
  function fillGeneratedPassword(expected, passwordValue, expiresAt) {
    "use strict";
    try {
      if (
        !Number.isSafeInteger(expiresAt) ||
        Date.now() >= expiresAt ||
        expiresAt - Date.now() > 2000 ||
        window !== window.top ||
        location.origin !== expected ||
        typeof passwordValue !== "string" ||
        passwordValue.length < 4 ||
        passwordValue.length > 256 ||
        !passwordValue.isWellFormed()
      )
        return false;
      function eligible(el) {
        if (
          !el ||
          !el.isConnected ||
          el.disabled ||
          el.readOnly ||
          el.matches(":disabled") ||
          el.matches("[data-1p-ignore],[data-locklark-ignore]") ||
          el.closest(
            '[hidden],[inert],[aria-hidden="true"],[data-1p-ignore],[data-locklark-ignore]',
          )
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
      function label(el) {
        return [el.name, el.id, el.placeholder, el.getAttribute?.("aria-label")]
          .filter((value) => typeof value === "string")
          .join(" ")
          .toLowerCase();
      }
      function isCurrent(el) {
        return (
          hasAutocomplete(el, "current-password") ||
          /current|old|existing/i.test(label(el))
        );
      }
      function isConfirm(el) {
        return /confirm|repeat|verify|again|retype/i.test(label(el));
      }
      function isNew(el) {
        return (
          hasAutocomplete(el, "new-password") ||
          /new.?pass|create.?pass|confirm.?pass|repeat.?pass|sign.?up|register|reset.?pass|change.?pass/i.test(
            label(el) + " " + (el.form?.getAttribute("action") || ""),
          )
        );
      }
      const passwords = [...document.querySelectorAll('input[type="password"]')]
        .filter(eligible);
      if (passwords.length < 1 || passwords.length > 3) return false;
      let target = null;
      if (document.activeElement?.type === "password")
        target = document.activeElement;
      if (!target || !passwords.includes(target)) {
        const containing = passwords.filter((el) => el.form === passwords[0].form);
        if (containing.length !== passwords.length) return false;
        target = passwords[0];
      }
      const group = passwords.filter((el) => el.form === target.form);
      if (group.length < 1 || group.length > 3) return false;
      let currentPass = null,
        newPass = null,
        confirmPass = null;
      if (group.length === 3) {
        currentPass = group[0];
        newPass = group[1];
        confirmPass = group[2];
      } else if (group.length === 2) {
        if (isCurrent(group[0]) && !isConfirm(group[1])) {
          currentPass = group[0];
          newPass = group[1];
        } else {
          newPass = group[0];
          confirmPass = group[1];
        }
      } else if (isNew(group[0])) {
        newPass = group[0];
      } else {
        // A single login/current-password field is never overwritten by the
        // generator. Only an explicit new-password field may be filled.
        return false;
      }
      if (!newPass) return false;
      const form = newPass.form;
      function sameAction(raw) {
        const u = new URL(raw || location.href, document.baseURI);
        return (
          u.protocol === "https:" &&
          u.origin === expected &&
          !u.username &&
          !u.password
        );
      }
      if (form && !sameAction(form.getAttribute("action"))) return false;
      if (form)
        for (const el of document.querySelectorAll(
          "button[formaction],input[formaction]",
        ))
          if (el.form === form && !sameAction(el.getAttribute("formaction")))
            return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      if (
        location.origin !== expected ||
        !eligible(newPass) ||
        newPass.form !== form ||
        (confirmPass && (!eligible(confirmPass) || confirmPass.form !== form)) ||
        Date.now() >= expiresAt
      )
        return false;
      const fields = confirmPass ? [newPass, confirmPass] : [newPass];
      for (const field of fields) setter.call(field, passwordValue);
      for (const field of fields) {
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }
      const user = [...document.querySelectorAll("input")]
        .filter(
          (el) =>
            ["text", "email"].includes(el.type) &&
            eligible(el) &&
            el.form === form &&
            (hasAutocomplete(el, "username") ||
              el.type === "email" ||
              /user|login|email/i.test(el.name || el.id)),
        )
        .at(0);
      return {
        ok: true,
        filledCount: fields.length,
        username: user
          ? Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")
              .get.call(user)
          : "",
        isPasswordChange: !!currentPass,
      };
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
    generatePassword,
    classifyPasswordFields,
    probe,
    fillDocument,
    fillGeneratedPassword,
    otpDocument,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
