/* Shared pure policy and static isolated-world injection functions. */
globalThis.LocklarkCore = (() => {
  "use strict";
  const IDENTITY_FIELDS = [
    "full_name",
    "first_name",
    "middle_name",
    "last_name",
    "title",
    "suffix",
    "company",
    "job_title",
    "street_address",
    "address_line1",
    "address_line2",
    "address_line3",
    "city",
    "state",
    "district",
    "postal_code",
    "country_code",
    "country_name",
    "phone",
    "phone_country_code",
    "email",
    "birth_date",
    "birth_year",
    "birth_month",
    "birth_day",
  ];
  const CARD_FIELDS = [
    "cardholder_name",
    "given_name",
    "additional_name",
    "family_name",
    "number",
    "exp",
    "exp_month",
    "exp_year",
    "cvv",
    "type",
  ];
  const IDENTITY_SET = new Set(IDENTITY_FIELDS);
  const CARD_SET = new Set(CARD_FIELDS);
  const CATEGORIES = new Set(["login", "identity", "credit_card"]);
  // W3C autocomplete field tokens. Section-* and address-scope modifiers are
  // stripped before this lookup.
  const AUTOCOMPLETE_FIELDS = {
    name: ["identity", "full_name"],
    "honorific-prefix": ["identity", "title"],
    "given-name": ["identity", "first_name"],
    "additional-name": ["identity", "middle_name"],
    "family-name": ["identity", "last_name"],
    "honorific-suffix": ["identity", "suffix"],
    organization: ["identity", "company"],
    "organization-title": ["identity", "job_title"],
    "street-address": ["identity", "street_address"],
    "address-line1": ["identity", "address_line1"],
    "address-line2": ["identity", "address_line2"],
    "address-line3": ["identity", "address_line3"],
    "address-level2": ["identity", "city"],
    "address-level1": ["identity", "state"],
    "address-level3": ["identity", "district"],
    "address-level4": ["identity", "district"],
    "postal-code": ["identity", "postal_code"],
    country: ["identity", "country_code"],
    "country-name": ["identity", "country_name"],
    tel: ["identity", "phone"],
    "tel-national": ["identity", "phone"],
    "tel-country-code": ["identity", "phone_country_code"],
    email: ["identity", "email"],
    bday: ["identity", "birth_date"],
    "bday-year": ["identity", "birth_year"],
    "bday-month": ["identity", "birth_month"],
    "bday-day": ["identity", "birth_day"],
    "cc-name": ["credit_card", "cardholder_name"],
    "cc-given-name": ["credit_card", "given_name"],
    "cc-additional-name": ["credit_card", "additional_name"],
    "cc-family-name": ["credit_card", "family_name"],
    "cc-number": ["credit_card", "number"],
    "cc-exp": ["credit_card", "exp"],
    "cc-exp-month": ["credit_card", "exp_month"],
    "cc-exp-year": ["credit_card", "exp_year"],
    "cc-csc": ["credit_card", "cvv"],
    "cc-type": ["credit_card", "type"],
  };
  const SCOPE_TOKENS = new Set([
    "shipping",
    "billing",
    "home",
    "work",
    "mobile",
    "fax",
    "pager",
  ]);
  const MONTHS = [
    ["january", "jan", "1", "01"],
    ["february", "feb", "2", "02"],
    ["march", "mar", "3", "03"],
    ["april", "apr", "4", "04"],
    ["may", "5", "05"],
    ["june", "jun", "6", "06"],
    ["july", "jul", "7", "07"],
    ["august", "aug", "8", "08"],
    ["september", "sep", "sept", "9", "09"],
    ["october", "oct", "10"],
    ["november", "nov", "11"],
    ["december", "dec", "12"],
  ];
  const COUNTRY_NAMES = {
    US: "united states",
    USA: "united states of america",
    CN: "china",
    GB: "united kingdom",
    UK: "united kingdom",
    CA: "canada",
    AU: "australia",
    NZ: "new zealand",
    JP: "japan",
    KR: "south korea",
    DE: "germany",
    FR: "france",
    IT: "italy",
    ES: "spain",
    NL: "netherlands",
    SE: "sweden",
    NO: "norway",
    DK: "denmark",
    FI: "finland",
    CH: "switzerland",
    AT: "austria",
    BE: "belgium",
    IE: "ireland",
    PT: "portugal",
    PL: "poland",
    CZ: "czechia",
    BR: "brazil",
    MX: "mexico",
    AR: "argentina",
    CL: "chile",
    IN: "india",
    SG: "singapore",
    MY: "malaysia",
    TH: "thailand",
    VN: "vietnam",
    ID: "indonesia",
    PH: "philippines",
    HK: "hong kong",
    TW: "taiwan",
    AE: "united arab emirates",
    SA: "saudi arabia",
    IL: "israel",
    TR: "türkiye",
    ZA: "south africa",
    NG: "nigeria",
    KE: "kenya",
    EG: "egypt",
    RU: "russia",
    UA: "ukraine",
  };
  const COUNTRY_CODES = (() => {
    const out = {};
    for (const [code, name] of Object.entries(COUNTRY_NAMES)) {
      const key = name.toLowerCase();
      if (!out[key] || code.length === 2) out[key] = code;
    }
    out["united states of america"] = "US";
    out["usa"] = "US";
    out["great britain"] = "GB";
    out["uk"] = "GB";
    out["south korea"] = "KR";
    out["republic of korea"] = "KR";
    out["czech republic"] = "CZ";
    out["russia"] = "RU";
    out["türkiye"] = "TR";
    out["turkey"] = "TR";
    return out;
  })();
  const US_STATES = {
    AL: "alabama",
    AK: "alaska",
    AZ: "arizona",
    AR: "arkansas",
    CA: "california",
    CO: "colorado",
    CT: "connecticut",
    DE: "delaware",
    FL: "florida",
    GA: "georgia",
    HI: "hawaii",
    ID: "idaho",
    IL: "illinois",
    IN: "indiana",
    IA: "iowa",
    KS: "kansas",
    KY: "kentucky",
    LA: "louisiana",
    ME: "maine",
    MD: "maryland",
    MA: "massachusetts",
    MI: "michigan",
    MN: "minnesota",
    MS: "mississippi",
    MO: "missouri",
    MT: "montana",
    NE: "nebraska",
    NV: "nevada",
    NH: "new hampshire",
    NJ: "new jersey",
    NM: "new mexico",
    NY: "new york",
    NC: "north carolina",
    ND: "north dakota",
    OH: "ohio",
    OK: "oklahoma",
    OR: "oregon",
    PA: "pennsylvania",
    RI: "rhode island",
    SC: "south carolina",
    SD: "south dakota",
    TN: "tennessee",
    TX: "texas",
    UT: "utah",
    VT: "vermont",
    VA: "virginia",
    WA: "washington",
    WV: "west virginia",
    WI: "wisconsin",
    WY: "wyoming",
    DC: "district of columbia",
    ON: "ontario",
    QC: "quebec",
    BC: "british columbia",
    AB: "alberta",
    MB: "manitoba",
    SK: "saskatchewan",
    NS: "nova scotia",
    NB: "new brunswick",
    NL: "newfoundland and labrador",
    PE: "prince edward island",
  };
  const US_STATE_CODES = (() => {
    const out = {};
    for (const [code, name] of Object.entries(US_STATES)) out[name] = code;
    return out;
  })();
  const MULTI_LABEL_SUFFIXES = new Set([
    "co.uk",
    "org.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "sch.uk",
    "ac.uk",
    "gov.uk",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "com.jp",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "co.nz",
    "org.nz",
    "net.nz",
    "govt.nz",
    "ac.nz",
    "com.br",
    "com.mx",
    "com.ar",
    "com.tr",
    "com.sg",
    "com.hk",
    "com.tw",
    "com.my",
    "co.in",
    "net.in",
    "org.in",
    "co.kr",
    "or.kr",
    "com.ru",
    "com.ua",
    "com.pl",
    "co.za",
    "org.za",
    "gov.za",
    "co.il",
    "org.il",
    "ac.il",
    "com.sa",
    "com.eg",
    "com.ng",
    "co.ke",
  ]);
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
  function siteKey(raw) {
    const origin = originFromURL(raw),
      host = new URL(origin).hostname,
      labels = host.split(".");
    const suffix = labels.slice(-2).join(".");
    const take = MULTI_LABEL_SUFFIXES.has(suffix) ? 3 : 2;
    return labels.slice(-take).join(".");
  }
  function sameSite(a, b) {
    return siteKey(a) === siteKey(b);
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
  function validFieldMap(value, allowed) {
    if (!value || typeof value !== "object" || Array.isArray(value))
      return false;
    const keys = Object.keys(value);
    if (keys.length > 32) return false;
    for (const key of keys) {
      if (!allowed.has(key) || typeof value[key] !== "string") return false;
      if (value[key].length > 16384) return false;
    }
    return true;
  }
  function hasOnly(object, allowed) {
    return Object.keys(object).every((key) => allowed.includes(key));
  }
  function validCategory(value) {
    return value === undefined || CATEGORIES.has(value);
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
        candidates: ["v", "id", "type", "candidates", "category"],
        fill: [
          "v",
          "id",
          "type",
          "username",
          "password",
          "category",
          "identity",
          "card",
        ],
        filled: ["v", "id", "type", "category", "identity", "card"],
        "filled-identity": ["v", "id", "type", "category", "identity", "card"],
        "filled-card": ["v", "id", "type", "category", "identity", "card"],
        error: ["v", "id", "type", "error"],
        cancelled: ["v", "id", "type"],
        "save-ready": ["v", "id", "type", "nonce"],
        "otp-ready": ["v", "id", "type", "nonce"],
        "otp-fill": ["v", "id", "type", "code"],
        saved: ["v", "id", "type", "item_id", "revision"],
        unknown: ["v", "id", "type"],
      },
      keys = shapes[m.type];
    if (!keys || !hasOnly(m, keys)) return false;
    if (m.type === "locked") return true;
    if (m.type === "unpaired") return m.error === "expired";
    if (!/^[a-f0-9]{32}$/.test(m.id || "")) return false;
    if (!validCategory(m.category)) return false;
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
                ["id", "revision", "title", "state", "category", "subtitle"].includes(
                  k,
                ),
              ) &&
              /^[a-f0-9]{32}$/.test(r.id || "") &&
              /^[a-f0-9]{64}$/.test(r.revision || "") &&
              typeof r.title === "string" &&
              r.title.length <= 1024 &&
              r.state === "active" &&
              validCategory(r.category) &&
              (r.subtitle === undefined ||
                (typeof r.subtitle === "string" && r.subtitle.length <= 1024)),
          ))
      );
    if (m.type === "fill") {
      if (m.category === "identity" || m.category === "credit_card") {
        if (m.category === "identity")
          return validFieldMap(m.identity, IDENTITY_SET) && m.card === undefined;
        return validFieldMap(m.card, CARD_SET) && m.identity === undefined;
      }
      return (
        m.identity === undefined &&
        m.card === undefined &&
        typeof m.username === "string" &&
        typeof m.password === "string" &&
        m.username.length <= 16384 &&
        m.password.length <= 16384
      );
    }
    if (m.type === "filled" || m.type === "filled-identity") {
      if (m.category !== undefined && m.category !== "identity") return false;
      return validFieldMap(m.identity, IDENTITY_SET) && m.card === undefined;
    }
    if (m.type === "filled-card") {
      if (m.category !== undefined && m.category !== "credit_card") return false;
      return validFieldMap(m.card, CARD_SET) && m.identity === undefined;
    }
    return true;
  }
  function queryAllDeep(root, selector, maxDepth = 8) {
    const out = [];
    let budget = 5000,
      depthLimit = Number.isSafeInteger(maxDepth) ? maxDepth : 8;
    function walk(node, depth) {
      if (!node || depth > depthLimit || budget <= 0) return;
      if (typeof node.querySelectorAll !== "function") return;
      let matches;
      try {
        matches = node.querySelectorAll(selector);
      } catch {
        return;
      }
      for (const el of matches) {
        out.push(el);
        if (--budget <= 0) return;
      }
      let all;
      try {
        all = node.querySelectorAll("*");
      } catch {
        return;
      }
      for (const el of all) {
        if (el && el.shadowRoot && el.shadowRoot.mode === "open")
          walk(el.shadowRoot, depth + 1);
      }
    }
    walk(root, 0);
    return out;
  }
  function eventInputTarget(event) {
    const path =
      event && typeof event.composedPath === "function"
        ? event.composedPath()
        : [];
    for (const node of path) {
      const tag = String((node && node.tagName) || "").toUpperCase();
      if (
        tag === "INPUT" ||
        tag === "SELECT" ||
        tag === "TEXTAREA" ||
        node instanceof HTMLInputElement ||
        node instanceof HTMLSelectElement ||
        node instanceof HTMLTextAreaElement
      )
        return node;
    }
    return event && event.target;
  }
  function eligibleControl(el) {
    if (!el || el.isConnected === false || el.disabled || el.readOnly) return false;
    const tag = String(el.tagName || "").toUpperCase();
    if (tag && !["INPUT", "SELECT", "TEXTAREA"].includes(tag)) return false;
    if (String(el.type || "").toLowerCase() === "hidden") return false;
    if (el.hidden) return false;
    if (typeof el.matches === "function" && el.matches(":disabled")) return false;
    let node = el;
    for (let depth = 0; node && depth < 64; depth++) {
      if (
        node.nodeType === 1 &&
        typeof node.matches === "function" &&
        node.matches('[hidden],[inert],[aria-hidden="true"]')
      )
        return false;
      if (node.nodeType === 1 && typeof getComputedStyle === "function") {
        const style = getComputedStyle(node);
        if (
          style &&
          (style.display === "none" ||
            style.visibility !== "visible" ||
            Number(style.opacity) === 0)
        )
          return false;
      }
      const parent = node.parentElement;
      if (parent) {
        node = parent;
        continue;
      }
      const root =
        typeof node.getRootNode === "function" ? node.getRootNode() : null;
      node =
        root && root !== node && root.host
          ? root.host
          : null;
    }
    if (typeof el.getClientRects === "function") {
      const rect = el.getBoundingClientRect();
      if (
        el.getClientRects().length === 0 ||
        !rect ||
        rect.width <= 0 ||
        rect.height <= 0
      )
        return false;
    }
    return true;
  }
  function autocompleteField(el) {
    let raw = "";
    try {
      raw = (el.getAttribute && el.getAttribute("autocomplete")) || "";
    } catch {}
    if (!raw && typeof el.autocomplete === "string") raw = el.autocomplete;
    if (!raw) return null;
    const tokens = String(raw)
      .toLowerCase()
      .trim()
      .split(/\s+/)
      .filter(
        (token) =>
          token && !/^section-/.test(token) && !SCOPE_TOKENS.has(token),
      );
    const token = tokens.at(-1);
    const found = token && AUTOCOMPLETE_FIELDS[token];
    return found ? { category: found[0], field: found[1] } : null;
  }
  function associatedLabel(el) {
    const pieces = [];
    try {
      if (el.labels && el.labels.length)
        for (const label of el.labels) pieces.push(label.textContent || "");
      if (el.id && typeof document !== "undefined" && document.querySelector) {
        const escaped =
          typeof CSS !== "undefined" && CSS.escape
            ? CSS.escape(el.id)
            : String(el.id).replace(/["\\]/g, "\\$&");
        const label = document.querySelector('label[for="' + escaped + '"]');
        if (label) pieces.push(label.textContent || "");
      }
      if (typeof el.closest === "function") {
        const label = el.closest("label");
        if (label) pieces.push(label.textContent || "");
      }
      const labelledBy = el.getAttribute && el.getAttribute("aria-labelledby");
      if (labelledBy && typeof document !== "undefined" && document.getElementById)
        for (const id of labelledBy.split(/\s+/))
          if (id) {
            const label = document.getElementById(id);
            if (label) pieces.push(label.textContent || "");
          }
    } catch {}
    return pieces.join(" ");
  }
  function fieldSignal(el) {
    const pieces = [];
    for (const value of [
      el.name,
      el.id,
      el.placeholder,
      el.getAttribute && el.getAttribute("aria-label"),
      el.getAttribute && el.getAttribute("title"),
      el.getAttribute && el.getAttribute("data-testid"),
      associatedLabel(el),
    ])
      if (value) pieces.push(String(value));
    return pieces.join(" ").replace(/\s+/g, " ").trim().toLowerCase();
  }
  function enclosingForm(el) {
    try {
      if (el.form) return el.form;
      if (typeof el.closest === "function") return el.closest("form");
    } catch {}
    return null;
  }
  function formHasPassword(el) {
    const form = enclosingForm(el);
    if (!form || typeof form.querySelectorAll !== "function") return false;
    try {
      return [...form.querySelectorAll('input[type="password"]')].length > 0;
    } catch {
      return false;
    }
  }
  function nearbyIdentityCount(el) {
    const form = enclosingForm(el);
    if (!form || typeof form.querySelectorAll !== "function") return 0;
    let count = 0;
    try {
      for (const field of form.querySelectorAll("input,select,textarea")) {
        if (
          /(address|city|state|province|postal|zip|country|first.?name|last.?name|street|phone|company|地址|城市|省|邮编|国家|公司|电话|姓名)/i.test(
            fieldSignal(field),
          )
        )
          count++;
      }
    } catch {}
    return count;
  }
  function classifyField(el) {
    if (!el) return null;
    const tag = String(el.tagName || "").toUpperCase();
    if (tag && !["INPUT", "SELECT", "TEXTAREA"].includes(tag)) return null;
    if (!tag && typeof el.type !== "string" && !el.options) return null;
    if (String(el.type || "").toLowerCase() === "hidden") return null;
    const explicit = autocompleteField(el);
    if (explicit) return explicit;
    const signal = fieldSignal(el);
    if (!signal) return null;
    const isSelect = tag === "SELECT" || !!el.options;
    const card = classifyCardSignal(signal);
    if (card) return { category: "credit_card", field: card };
    const identity = classifyIdentitySignal(el, signal, isSelect);
    if (identity) return { category: "identity", field: identity };
    return null;
  }
  function classifyCardSignal(signal) {
    if (/(card.?holder|name.?on.?(?:the.?)?card|cc.?name|持卡人|卡片姓名)/i.test(signal))
      return "cardholder_name";
    if (/(card.?type|cc.?type|card.?brand|卡类型|发卡组织|卡组织)/i.test(signal))
      return "type";
    if (/(cvv|cvc|csc|cvn|security.?code|card.?verification|安全码|校验码)/i.test(signal))
      return "cvv";
    if (
      /(exp(?:iry|iration)?[\s_.-]*(?:month|mm|mon)|cc.?exp.?month|exp.?mon)/i.test(
        signal,
      ) ||
      (/(?:月份|有效月)/.test(signal) && /(卡|信用|有效|到期|exp|cc)/i.test(signal))
    )
      return "exp_month";
    if (
      /(exp(?:iry|iration)?[\s_.-]*(?:year|yy|yyyy)|cc.?exp.?year|exp.?year)/i.test(
        signal,
      ) ||
      (/(?:年份|有效年)/.test(signal) && /(卡|信用|有效|到期|exp|cc)/i.test(signal))
    )
      return "exp_year";
    if (/(exp(?:iry|iration)?(?:[\s_.-]*date)?|cc.?exp|mm\s*[/-]\s*yy|有效期|到期日)/i.test(signal))
      return "exp";
    if (/(card.?number|cc.?num|credit.?card.?number|card[_ -]?no|\bpan\b|卡号|银行卡号|信用卡号)/i.test(signal))
      return "number";
    if (/(first.?name.?on.?card|cc.?given.?name)/i.test(signal)) return "given_name";
    if (/(last.?name.?on.?card|cc.?family.?name)/i.test(signal)) return "family_name";
    if (/(middle.?name.?on.?card|cc.?additional.?name)/i.test(signal))
      return "additional_name";
    return null;
  }
  function classifyIdentitySignal(el, signal, isSelect) {
    if (
      /(username|user.?name|login|sign.?in|account|password|搜索|search|邮箱验证|登录)/i.test(
        signal,
      )
    )
      return null;
    if (/(middle.?name|mname|中间名)/i.test(signal)) return "middle_name";
    if (/(full.?name|your.?name|contact.?name|recipient.?name|姓名|全名|收件人)/i.test(signal))
      return "full_name";
    if (/(first.?name|given.?name|fname|forename|名字|名(?!称|字))/i.test(signal))
      return "first_name";
    if (/(last.?name|family.?name|surname|lname|姓氏|姓(?!名))/i.test(signal))
      return "last_name";
    if (/(job.?title|position|occupation|role|职位|职务|头衔)/i.test(signal))
      return "job_title";
    if (/(honorific|salutation|prefix|称呼|称谓|尊称)/i.test(signal)) return "title";
    if (/(suffix|generational|后缀)/i.test(signal)) return "suffix";
    if (/(company|organization|organisation|org.?name|employer|公司|单位|组织)/i.test(signal))
      return "company";
    if (/(address.?line.?2|addr2|apt|suite|unit|building|floor|address_2|地址2|门牌|单元|楼层)/i.test(signal))
      return "address_line2";
    if (/(address.?line.?3|addr3|address_3|地址3)/i.test(signal)) return "address_line3";
    if (/(address.?line.?1|addr1|address_1|详细地址|街道地址|地址1|地址)/i.test(signal))
      return "address_line1";
    if (/(street.?address|street.?name|街道)/i.test(signal)) return "street_address";
    if (/(city|town|locality|城市|市(?!场))/i.test(signal)) return "city";
    if (/(state|province|region|prefecture|county|省份|省|州)/i.test(signal))
      return "state";
    if (/(district|suburb|区县|区|县)/i.test(signal)) return "district";
    if (/(postal.?code|zip.?code|\bzip\b|postcode|pincode|邮编|邮政编码)/i.test(signal))
      return "postal_code";
    if (/(country|nation|国家|地区)/i.test(signal)) {
      if (/(country.?code|国家代码|代码)/i.test(signal)) return "country_code";
      if (/(country.?name|国家名称|国家名)/i.test(signal)) return "country_name";
      if (isSelect) {
        const options = [...(el.options || [])];
        if (
          options.length > 1 &&
          options.every(
            (option) =>
              !option.value || /^[A-Za-z]{2}$/.test(String(option.value).trim()),
          )
        )
          return "country_code";
      }
      return "country_name";
    }
    if (/(phone.?country.?code|country.?code.*phone|dial.?code|国际区号|电话区号)/i.test(signal))
      return "phone_country_code";
    if (/(phone|mobile|telephone|\bcell\b|\btel\b|手机|电话|联系电话|联系方式)/i.test(signal)) {
      if (formHasPassword(el) && nearbyIdentityCount(el) < 2) return null;
      return "phone";
    }
    if (String(el.type || "").toLowerCase() === "email" || /(e-?mail|邮箱|电子邮件)/i.test(signal)) {
      if (formHasPassword(el) && nearbyIdentityCount(el) < 2) return null;
      return "email";
    }
    if (/(birth.?year|year.?of.?birth|出生年|生日年)/i.test(signal)) return "birth_year";
    if (/(birth.?month|month.?of.?birth|出生月|生日月)/i.test(signal))
      return "birth_month";
    if (/(birth.?day|day.?of.?birth|出生日|生日日)/i.test(signal)) return "birth_day";
    if (/(birth.?date|birthday|\bdob\b|date.?of.?birth|生日|出生日期)/i.test(signal))
      return "birth_date";
    return null;
  }
  function inspectAutofillFields(root) {
    const scope =
      root && typeof root.querySelectorAll === "function"
        ? root
        : typeof document !== "undefined"
          ? document
          : null;
    if (!scope) return [];
    const out = [];
    for (const el of queryAllDeep(scope, "input,select,textarea")) {
      if (!eligibleControl(el)) continue;
      const found = classifyField(el);
      if (found)
        out.push({ element: el, category: found.category, field: found.field });
    }
    return out;
  }
  function optionsOf(select) {
    try {
      return Array.from(select.options || []);
    } catch {
      return [];
    }
  }
  function monthTargets(value) {
    const raw = String(value).trim(),
      number = Number(raw);
    const targets = new Set([raw, raw.padStart(2, "0"), raw.replace(/^0/, "")]);
    if (Number.isInteger(number) && number >= 1 && number <= 12) {
      targets.add(String(number));
      targets.add(String(number).padStart(2, "0"));
      for (const name of MONTHS[number - 1]) targets.add(name);
      targets.add(number + "月");
    }
    return [...targets].filter(Boolean);
  }
  function yearTargets(value) {
    const raw = String(value).trim();
    const digits = raw.match(/\d{2,4}/)?.[0] || raw;
    const targets = new Set([raw, digits]);
    if (digits.length === 2) targets.add("20" + digits);
    if (digits.length === 4) targets.add(digits.slice(-2));
    return [...targets].filter(Boolean);
  }
  function countryTargets(value) {
    const raw = String(value).trim(),
      upper = raw.toUpperCase(),
      targets = new Set([raw, upper]);
    const name = COUNTRY_NAMES[upper];
    if (name) {
      targets.add(name);
      for (const [code, candidate] of Object.entries(COUNTRY_NAMES))
        if (candidate === name && code.length === 2) targets.add(code);
    }
    const code = COUNTRY_CODES[raw.toLowerCase()];
    if (code) {
      targets.add(code);
      if (COUNTRY_NAMES[code]) targets.add(COUNTRY_NAMES[code]);
    }
    if (upper === "US") {
      targets.add("usa");
      targets.add("united states of america");
      targets.add("u.s.");
      targets.add("u.s.a.");
    }
    return [...targets].filter(Boolean);
  }
  function stateTargets(value) {
    const raw = String(value).trim(),
      upper = raw.toUpperCase(),
      targets = new Set([raw, upper]);
    if (US_STATES[upper]) targets.add(US_STATES[upper]);
    const code = US_STATE_CODES[raw.toLowerCase()];
    if (code) targets.add(code);
    return [...targets].filter(Boolean);
  }
  function selectOptionMatch(select, value, field) {
    const raw = String(value == null ? "" : value).trim();
    const options = optionsOf(select);
    if (!options.length) return null;
    if (!raw) {
      const fallback =
        options.find((option) => option.defaultSelected) || options[0];
      return fallback ? String(fallback.value) : "";
    }
    let targets;
    if (field === "exp_month" || field === "month" || field === "birth_month")
      targets = monthTargets(raw);
    else if (field === "exp_year" || field === "year" || field === "birth_year")
      targets = yearTargets(raw);
    else if (field === "country_code" || field === "country_name" || field === "country")
      targets = countryTargets(raw);
    else if (field === "state" || field === "address-level1")
      targets = stateTargets(raw);
    else targets = [raw];
    const lowered = targets.map((target) => String(target).toLowerCase());
    const usable = options.filter(
      (option) =>
        !option.disabled &&
        String(option.value == null ? "" : option.value).trim() !== "",
    );
    const exactValue = usable.find((option) =>
      lowered.includes(String(option.value).trim().toLowerCase()),
    );
    if (exactValue) return String(exactValue.value);
    const exactText = usable.find((option) =>
      lowered.includes(String(option.text || "").trim().toLowerCase()),
    );
    if (exactText) return String(exactText.value);
    for (const target of targets) {
      const number = Number(String(target).trim());
      if (!Number.isFinite(number)) continue;
      const numeric = usable.find(
        (option) =>
          String(option.value).trim() !== "" &&
          Number(String(option.value).trim()) === number,
      );
      if (numeric) return String(numeric.value);
    }
    for (const option of usable) {
      const text = String(option.text || "").trim().toLowerCase();
      const optionValue = String(option.value).trim().toLowerCase();
      for (const target of lowered) {
        if (!target) continue;
        if (text === target || optionValue === target) return String(option.value);
        if (text.startsWith(target + " ") || text.startsWith(target + "-") ||
            text.startsWith(target + " -") || text.includes(target))
          return String(option.value);
      }
    }
    return null;
  }
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
    allowSubframe,
  ) {
    "use strict";
    try {
      function frameAllowed() {
        if (window === window.top) return true;
        if (allowSubframe !== true) return false;
        try {
          return (
            window.top.location.origin === location.origin &&
            location.origin !== "null"
          );
        } catch {
          return false;
        }
      }
      if (
        !Number.isSafeInteger(expiresAt) ||
        Date.now() >= expiresAt ||
        expiresAt - Date.now() > 2000 ||
        !frameAllowed() ||
        (location.protocol !== undefined && location.protocol !== "https:") ||
        location.origin !== expected ||
        typeof username !== "string" ||
        typeof password !== "string" ||
        username.length > 16384 ||
        password.length > 16384
      )
        return false;
      function deepAll(root, selector) {
        const out = [];
        let budget = 5000;
        function walk(node, depth) {
          if (!node || depth > 8 || budget <= 0) return;
          let matches;
          try {
            matches = node.querySelectorAll(selector);
          } catch {
            return;
          }
          for (const el of matches) {
            out.push(el);
            if (--budget <= 0) return;
          }
          let all;
          try {
            all = node.querySelectorAll("*");
          } catch {
            return;
          }
          for (const el of all)
            if (el && el.shadowRoot && el.shadowRoot.mode === "open")
              walk(el.shadowRoot, depth + 1);
        }
        walk(root, 0);
        return out;
      }
      function rootNode(el) {
        try {
          const root = el.getRootNode && el.getRootNode();
          return root && root.host ? root : null;
        } catch {
          return null;
        }
      }
      function logicalForm(el) {
        try {
          if (el.form) return el.form;
          const form = el.closest && el.closest("form");
          if (form) return form;
          return rootNode(el);
        } catch {
          return null;
        }
      }
      function eligible(el) {
        if (
          !el ||
          el.isConnected === false ||
          el.disabled ||
          el.readOnly ||
          el.matches(":disabled") ||
          el.closest('[hidden],[inert],[aria-hidden="true"]')
        )
          return false;
        for (let n = el; n instanceof Element; ) {
          const s = getComputedStyle(n);
          if (
            s.display === "none" ||
            s.visibility !== "visible" ||
            Number(s.opacity) === 0
          )
            return false;
          let next = n.parentElement;
          if (!next) {
            const root = rootNode(n);
            next = root ? root.host : null;
          }
          n = next;
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
      const allInputs = deepAll(document, "input");
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
        passwords.some((e) => hasAutocomplete(e, "new-password"))
      )
        return false;
      let pass = passwords[0] || null;
      let users = visible.filter(
        (e) =>
          ["text", "email"].includes(e.type) &&
          (!pass || logicalForm(e) === logicalForm(pass)),
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
        form = logicalForm(pass || user);
      if (!form)
        return false;
      if (
        form.ownerDocument &&
        form.ownerDocument !== document
      )
        return false;
      if (pass && user && logicalForm(pass) !== logicalForm(user)) return false;
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
          (e) =>
            ["text", "email"].includes(e.type) &&
            logicalForm(e) === logicalForm(pass),
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
      function actionOf(target) {
        return target && typeof target.getAttribute === "function"
          ? target.getAttribute("action")
          : null;
      }
      if (!sameAction(actionOf(form))) return false;
      for (const el of deepAll(document, "button[formaction],input[formaction]"))
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
        (user && (!eligible(user) || logicalForm(user) !== form)) ||
        (pass && (!eligible(pass) || logicalForm(pass) !== form)) ||
        !sameAction(actionOf(form)) ||
        Date.now() >= expiresAt
      )
        return false;
      if (captureOnly) {
        const get = Object.getOwnPropertyDescriptor(
          HTMLInputElement.prototype,
          "value",
        ).get;
        const capturedUsername = get.call(user),
          capturedPassword = get.call(pass);
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
          !valid(capturedUsername) ||
          !valid(capturedPassword) ||
          capturedPassword.length === 0 ||
          Date.now() >= expiresAt
        )
          return false;
        return { username: capturedUsername, password: capturedPassword };
      }
      if (user) set.call(user, username);
      if (pass) set.call(pass, password);
      for (const field of [user, pass].filter(Boolean)) {
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }
      const step = user && pass ? "combined" : user ? "username-only" : "password-only";
      let submitted = false;
      const isForm =
        form &&
        typeof form.requestSubmit === "function" &&
        typeof form.getAttribute === "function" &&
        form.ownerDocument === document;
      if (autoLogin === true && isForm && form.method?.toLowerCase() === "post") {
        const elements =
          form.elements && typeof form.elements[Symbol.iterator] === "function"
            ? [...form.elements]
            : [];
        const submitters = elements.filter(
          (e) =>
            (e instanceof HTMLButtonElement || e instanceof HTMLInputElement) &&
            e.type === "submit" &&
            eligible(e),
        );
        const button = submitters.length === 1 ? submitters[0] : null;
        const label =
          button &&
          (
            (button.textContent || "") +
            " " +
            (button.value || "") +
            " " +
            (form.getAttribute("action") || "")
          );
        const destructive =
          label &&
          /register|sign.?up|reset|change|delete|purchase|pay/i.test(label);
        const positive =
          label &&
          /^(?:\s*)(next|continue|sign.?in|log.?in|submit|verify|下一步|继续|登录|提交|验证)(?:\s*)$/i.test(
            (button.textContent || button.value || "").trim(),
          );
        const allowCombined =
          step === "combined" &&
          hasAutocomplete(pass, "current-password");
        const allowUsername = step === "username-only" && positive;
        const allowPassword = step === "password-only" && !destructive;
        if (
          button &&
          !destructive &&
          (allowCombined || allowUsername || allowPassword) &&
          form.isConnected &&
          (!user || (eligible(user) && logicalForm(user) === form)) &&
          (!pass || (eligible(pass) && logicalForm(pass) === form)) &&
          location.origin === expected &&
          Date.now() < expiresAt &&
          sameAction(form.getAttribute("action")) &&
          sameAction(button.getAttribute("formaction") || form.getAttribute("action"))
        ) {
          HTMLFormElement.prototype.requestSubmit.call(form, button);
          submitted = true;
        }
      }
      return { ok: true, step, submitted };
    } catch {
      return false;
    }
  }
  // Self-contained on purpose: scripting.executeScript serializes this function
  // into the target frame's isolated world. Identity and card share one body so
  // both named exports remain independently injectable.
  function autofillDocument(
    expectedOrigin,
    data,
    expiresAt,
    allowSubframe,
    categoryHint,
  ) {
    "use strict";
    try {
      const IDENTITY = [
        "full_name",
        "first_name",
        "middle_name",
        "last_name",
        "title",
        "suffix",
        "company",
        "job_title",
        "street_address",
        "address_line1",
        "address_line2",
        "address_line3",
        "city",
        "state",
        "district",
        "postal_code",
        "country_code",
        "country_name",
        "phone",
        "phone_country_code",
        "email",
        "birth_date",
        "birth_year",
        "birth_month",
        "birth_day",
      ];
      const CARD = [
        "cardholder_name",
        "given_name",
        "additional_name",
        "family_name",
        "number",
        "exp",
        "exp_month",
        "exp_year",
        "cvv",
        "type",
      ];
      const AUTOCOMPLETE = {
        name: ["identity", "full_name"],
        "honorific-prefix": ["identity", "title"],
        "given-name": ["identity", "first_name"],
        "additional-name": ["identity", "middle_name"],
        "family-name": ["identity", "last_name"],
        "honorific-suffix": ["identity", "suffix"],
        organization: ["identity", "company"],
        "organization-title": ["identity", "job_title"],
        "street-address": ["identity", "street_address"],
        "address-line1": ["identity", "address_line1"],
        "address-line2": ["identity", "address_line2"],
        "address-line3": ["identity", "address_line3"],
        "address-level2": ["identity", "city"],
        "address-level1": ["identity", "state"],
        "address-level3": ["identity", "district"],
        "postal-code": ["identity", "postal_code"],
        country: ["identity", "country_code"],
        "country-name": ["identity", "country_name"],
        tel: ["identity", "phone"],
        "tel-national": ["identity", "phone"],
        "tel-country-code": ["identity", "phone_country_code"],
        email: ["identity", "email"],
        bday: ["identity", "birth_date"],
        "bday-year": ["identity", "birth_year"],
        "bday-month": ["identity", "birth_month"],
        "bday-day": ["identity", "birth_day"],
        "cc-name": ["credit_card", "cardholder_name"],
        "cc-given-name": ["credit_card", "given_name"],
        "cc-additional-name": ["credit_card", "additional_name"],
        "cc-family-name": ["credit_card", "family_name"],
        "cc-number": ["credit_card", "number"],
        "cc-exp": ["credit_card", "exp"],
        "cc-exp-month": ["credit_card", "exp_month"],
        "cc-exp-year": ["credit_card", "exp_year"],
        "cc-csc": ["credit_card", "cvv"],
        "cc-type": ["credit_card", "type"],
      };
      const MONTHS = [
        ["january", "jan"],
        ["february", "feb"],
        ["march", "mar"],
        ["april", "apr"],
        ["may"],
        ["june", "jun"],
        ["july", "jul"],
        ["august", "aug"],
        ["september", "sep", "sept"],
        ["october", "oct"],
        ["november", "nov"],
        ["december", "dec"],
      ];
      const COUNTRY_NAMES = {
        US: "united states",
        CN: "china",
        GB: "united kingdom",
        CA: "canada",
        AU: "australia",
        NZ: "new zealand",
        JP: "japan",
        KR: "south korea",
        DE: "germany",
        FR: "france",
        IT: "italy",
        ES: "spain",
        NL: "netherlands",
        SE: "sweden",
        NO: "norway",
        DK: "denmark",
        FI: "finland",
        CH: "switzerland",
        AT: "austria",
        BE: "belgium",
        IE: "ireland",
        PT: "portugal",
        PL: "poland",
        CZ: "czechia",
        BR: "brazil",
        MX: "mexico",
        AR: "argentina",
        IN: "india",
        SG: "singapore",
        MY: "malaysia",
        TH: "thailand",
        VN: "vietnam",
        ID: "indonesia",
        PH: "philippines",
        HK: "hong kong",
        TW: "taiwan",
        AE: "united arab emirates",
        SA: "saudi arabia",
        IL: "israel",
        TR: "türkiye",
        ZA: "south africa",
        RU: "russia",
        UA: "ukraine",
      };
      const COUNTRY_CODES = {};
      for (const [code, name] of Object.entries(COUNTRY_NAMES)) {
        if (!COUNTRY_CODES[name] || code.length === 2)
          COUNTRY_CODES[name] = code;
      }
      COUNTRY_CODES["united states of america"] = "US";
      COUNTRY_CODES.usa = "US";
      COUNTRY_CODES["great britain"] = "GB";
      COUNTRY_CODES.uk = "GB";
      COUNTRY_CODES["south korea"] = "KR";
      COUNTRY_CODES["czech republic"] = "CZ";
      COUNTRY_CODES.turkey = "TR";
      const STATES = {
        AL: "alabama",
        AK: "alaska",
        AZ: "arizona",
        AR: "arkansas",
        CA: "california",
        CO: "colorado",
        CT: "connecticut",
        DE: "delaware",
        FL: "florida",
        GA: "georgia",
        HI: "hawaii",
        ID: "idaho",
        IL: "illinois",
        IN: "indiana",
        IA: "iowa",
        KS: "kansas",
        KY: "kentucky",
        LA: "louisiana",
        ME: "maine",
        MD: "maryland",
        MA: "massachusetts",
        MI: "michigan",
        MN: "minnesota",
        MS: "mississippi",
        MO: "missouri",
        MT: "montana",
        NE: "nebraska",
        NV: "nevada",
        NH: "new hampshire",
        NJ: "new jersey",
        NM: "new mexico",
        NY: "new york",
        NC: "north carolina",
        ND: "north dakota",
        OH: "ohio",
        OK: "oklahoma",
        OR: "oregon",
        PA: "pennsylvania",
        RI: "rhode island",
        SC: "south carolina",
        SD: "south dakota",
        TN: "tennessee",
        TX: "texas",
        UT: "utah",
        VT: "vermont",
        VA: "virginia",
        WA: "washington",
        WV: "west virginia",
        WI: "wisconsin",
        WY: "wyoming",
        DC: "district of columbia",
        ON: "ontario",
        QC: "quebec",
        BC: "british columbia",
        AB: "alberta",
        MB: "manitoba",
        SK: "saskatchewan",
        NS: "nova scotia",
        NB: "new brunswick",
        PE: "prince edward island",
      };
      const STATE_CODES = {};
      for (const [code, name] of Object.entries(STATES)) STATE_CODES[name] = code;
      function frameAllowed() {
        if (window === window.top) return true;
        if (allowSubframe !== true) return false;
        try {
          return (
            window.top.location.origin === location.origin &&
            location.origin !== "null"
          );
        } catch {
          return false;
        }
      }
      if (
        !Number.isSafeInteger(expiresAt) ||
        Date.now() >= expiresAt ||
        expiresAt - Date.now() > 2000 ||
        !frameAllowed() ||
        (location.protocol !== undefined && location.protocol !== "https:") ||
        location.origin !== expectedOrigin ||
        !data ||
        typeof data !== "object" ||
        Array.isArray(data)
      )
        return false;
      let category = categoryHint;
      if (category !== "identity" && category !== "credit_card") {
        const keys = Object.keys(data);
        const cardHits = keys.filter((key) => CARD.includes(key)).length;
        const identityHits = keys.filter((key) => IDENTITY.includes(key)).length;
        if (cardHits && !identityHits) category = "credit_card";
        else if (identityHits && !cardHits) category = "identity";
        else return false;
      }
      const allowed = category === "identity" ? IDENTITY : CARD;
      const keys = Object.keys(data);
      if (keys.length > 32) return false;
      for (const key of keys) {
        if (!allowed.includes(key) || typeof data[key] !== "string") return false;
        if (data[key].length > 16384) return false;
      }
      function deepAll(root, selector) {
        const out = [];
        let budget = 5000;
        function walk(node, depth) {
          if (!node || depth > 8 || budget <= 0) return;
          let matches;
          try {
            matches = node.querySelectorAll(selector);
          } catch {
            return;
          }
          for (const el of matches) {
            out.push(el);
            if (--budget <= 0) return;
          }
          let all;
          try {
            all = node.querySelectorAll("*");
          } catch {
            return;
          }
          for (const el of all)
            if (el && el.shadowRoot && el.shadowRoot.mode === "open")
              walk(el.shadowRoot, depth + 1);
        }
        walk(root, 0);
        return out;
      }
      function rootNode(el) {
        try {
          const root = el.getRootNode && el.getRootNode();
          return root && root.host ? root : null;
        } catch {
          return null;
        }
      }
      function eligible(el) {
        if (
          !el ||
          el.isConnected === false ||
          el.disabled ||
          el.readOnly ||
          String(el.type || "").toLowerCase() === "hidden" ||
          el.hidden ||
          el.matches(":disabled") ||
          el.closest('[hidden],[inert],[aria-hidden="true"]')
        )
          return false;
        for (let node = el; node instanceof Element; ) {
          const style = getComputedStyle(node);
          if (
            style.display === "none" ||
            style.visibility !== "visible" ||
            Number(style.opacity) === 0
          )
            return false;
          let next = node.parentElement;
          if (!next) {
            const root = rootNode(node);
            next = root ? root.host : null;
          }
          node = next;
        }
        const rect = el.getBoundingClientRect();
        return (
          el.getClientRects().length > 0 && rect.width > 0 && rect.height > 0
        );
      }
      function labelText(el) {
        const pieces = [];
        try {
          if (el.labels && el.labels.length)
            for (const label of el.labels) pieces.push(label.textContent || "");
          if (el.id && typeof document.querySelector === "function") {
            const escaped =
              typeof CSS !== "undefined" && CSS.escape
                ? CSS.escape(el.id)
                : String(el.id).replace(/["\\]/g, "\\$&");
            const label = document.querySelector('label[for="' + escaped + '"]');
            if (label) pieces.push(label.textContent || "");
          }
          if (typeof el.closest === "function") {
            const label = el.closest("label");
            if (label) pieces.push(label.textContent || "");
          }
          const labelledBy =
            el.getAttribute && el.getAttribute("aria-labelledby");
          if (labelledBy)
            for (const id of labelledBy.split(/\s+/)) {
              if (!id) continue;
              const label = document.getElementById(id);
              if (label) pieces.push(label.textContent || "");
            }
        } catch {}
        return pieces.join(" ");
      }
      function signalOf(el) {
        const pieces = [];
        for (const value of [
          el.name,
          el.id,
          el.placeholder,
          el.getAttribute && el.getAttribute("aria-label"),
          el.getAttribute && el.getAttribute("title"),
          el.getAttribute && el.getAttribute("data-testid"),
          labelText(el),
        ])
          if (value) pieces.push(String(value));
        return pieces.join(" ").replace(/\s+/g, " ").trim().toLowerCase();
      }
      function formOf(el) {
        try {
          return (
            el.form ||
            (el.closest && el.closest("form")) ||
            rootNode(el) ||
            null
          );
        } catch {
          return null;
        }
      }
      function formHasPassword(el) {
        const form = formOf(el);
        if (!form || typeof form.querySelectorAll !== "function") return false;
        try {
          return form.querySelectorAll('input[type="password"]').length > 0;
        } catch {
          return false;
        }
      }
      function nearbyIdentityCount(el) {
        const form = formOf(el);
        if (!form || typeof form.querySelectorAll !== "function") return 0;
        let count = 0;
        try {
          for (const field of form.querySelectorAll("input,select,textarea"))
            if (
              /(address|city|state|province|postal|zip|country|first.?name|last.?name|street|phone|company|地址|城市|省|邮编|国家|公司|电话|姓名)/i.test(
                signalOf(field),
              )
            )
              count++;
        } catch {}
        return count;
      }
      function autoKey(el, wanted) {
        let raw = "";
        try {
          raw = (el.getAttribute && el.getAttribute("autocomplete")) || "";
        } catch {}
        if (!raw && typeof el.autocomplete === "string") raw = el.autocomplete;
        if (!raw) return null;
        const tokens = String(raw)
          .toLowerCase()
          .trim()
          .split(/\s+/)
          .filter(
            (token) =>
              token &&
              !/^section-/.test(token) &&
              !["shipping", "billing", "home", "work", "mobile", "fax", "pager"].includes(
                token,
              ),
          );
        const found = AUTOCOMPLETE[tokens.at(-1)];
        return found && found[0] === wanted ? found[1] : null;
      }
      function cardKey(signal) {
        if (/(card.?holder|name.?on.?(?:the.?)?card|cc.?name|持卡人|卡片姓名)/i.test(signal))
          return "cardholder_name";
        if (/(card.?type|cc.?type|card.?brand|卡类型|发卡组织|卡组织)/i.test(signal))
          return "type";
        if (/(cvv|cvc|csc|cvn|security.?code|card.?verification|安全码|校验码)/i.test(signal))
          return "cvv";
        if (
          /(exp(?:iry|iration)?[\s_.-]*(?:month|mm|mon)|cc.?exp.?month|exp.?mon)/i.test(
            signal,
          ) ||
          (/(?:月份|有效月)/.test(signal) && /(卡|信用|有效|到期|exp|cc)/i.test(signal))
        )
          return "exp_month";
        if (
          /(exp(?:iry|iration)?[\s_.-]*(?:year|yy|yyyy)|cc.?exp.?year|exp.?year)/i.test(
            signal,
          ) ||
          (/(?:年份|有效年)/.test(signal) && /(卡|信用|有效|到期|exp|cc)/i.test(signal))
        )
          return "exp_year";
        if (/(exp(?:iry|iration)?(?:[\s_.-]*date)?|cc.?exp|mm\s*[/-]\s*yy|有效期|到期日)/i.test(signal))
          return "exp";
        if (/(card.?number|cc.?num|credit.?card.?number|card[_ -]?no|\bpan\b|卡号|银行卡号|信用卡号)/i.test(signal))
          return "number";
        if (/(first.?name.?on.?card|cc.?given.?name)/i.test(signal))
          return "given_name";
        if (/(last.?name.?on.?card|cc.?family.?name)/i.test(signal))
          return "family_name";
        if (/(middle.?name.?on.?card|cc.?additional.?name)/i.test(signal))
          return "additional_name";
        return null;
      }
      function identityKey(el, signal, isSelect) {
        if (
          /(username|user.?name|login|sign.?in|account|password|搜索|search|登录)/i.test(
            signal,
          )
        )
          return null;
        if (/(card|credit.?card|cc.?|cardholder|持卡人|卡号|安全码|cvv|cvc)/i.test(signal))
          return null;
        if (/(middle.?name|mname|中间名)/i.test(signal)) return "middle_name";
        if (/(full.?name|your.?name|contact.?name|recipient.?name|姓名|全名|收件人)/i.test(signal))
          return "full_name";
        if (/(first.?name|given.?name|fname|forename|名字|名(?!称|字))/i.test(signal))
          return "first_name";
        if (/(last.?name|family.?name|surname|lname|姓氏|姓(?!名))/i.test(signal))
          return "last_name";
        if (/(job.?title|position|occupation|role|职位|职务|头衔)/i.test(signal))
          return "job_title";
        if (/(honorific|salutation|prefix|称呼|称谓|尊称)/i.test(signal)) return "title";
        if (/(suffix|generational|后缀)/i.test(signal)) return "suffix";
        if (/(company|organization|organisation|org.?name|employer|公司|单位|组织)/i.test(signal))
          return "company";
        if (/(address.?line.?2|addr2|apt|suite|unit|building|floor|address_2|地址2|门牌|单元|楼层)/i.test(signal))
          return "address_line2";
        if (/(address.?line.?3|addr3|address_3|地址3)/i.test(signal))
          return "address_line3";
        if (/(address.?line.?1|addr1|address_1|详细地址|街道地址|地址1|地址)/i.test(signal))
          return "address_line1";
        if (/(street.?address|street.?name|街道)/i.test(signal))
          return "street_address";
        if (/(city|town|locality|城市|市(?!场))/i.test(signal)) return "city";
        if (/(state|province|region|prefecture|county|省份|省|州)/i.test(signal))
          return "state";
        if (/(district|suburb|区县|区|县)/i.test(signal)) return "district";
        if (/(postal.?code|zip.?code|\bzip\b|postcode|pincode|邮编|邮政编码)/i.test(signal))
          return "postal_code";
        if (/(country|nation|国家|地区)/i.test(signal)) {
          if (/(country.?code|国家代码|代码)/i.test(signal)) return "country_code";
          if (/(country.?name|国家名称|国家名)/i.test(signal)) return "country_name";
          if (isSelect) {
            const options = [...(el.options || [])];
            if (
              options.length > 1 &&
              options.every(
                (option) =>
                  !option.value ||
                  /^[A-Za-z]{2}$/.test(String(option.value).trim()),
              )
            )
              return "country_code";
          }
          return "country_name";
        }
        if (/(phone.?country.?code|dial.?code|国际区号|电话区号)/i.test(signal))
          return "phone_country_code";
        if (/(phone|mobile|telephone|\bcell\b|\btel\b|手机|电话|联系电话|联系方式)/i.test(signal)) {
          if (formHasPassword(el) && nearbyIdentityCount(el) < 2) return null;
          return "phone";
        }
        if (String(el.type || "").toLowerCase() === "email" || /(e-?mail|邮箱|电子邮件)/i.test(signal)) {
          if (formHasPassword(el) && nearbyIdentityCount(el) < 2) return null;
          return "email";
        }
        if (/(birth.?year|year.?of.?birth|出生年|生日年)/i.test(signal))
          return "birth_year";
        if (/(birth.?month|month.?of.?birth|出生月|生日月)/i.test(signal))
          return "birth_month";
        if (/(birth.?day|day.?of.?birth|出生日|生日日)/i.test(signal))
          return "birth_day";
        if (/(birth.?date|birthday|\bdob\b|date.?of.?birth|生日|出生日期)/i.test(signal))
          return "birth_date";
        return null;
      }
      function classify(el, wanted) {
        const tag = String(el.tagName || "").toUpperCase();
        if (tag && !["INPUT", "SELECT", "TEXTAREA"].includes(tag)) return null;
        const explicit = autoKey(el, wanted);
        if (explicit) return explicit;
        const signal = signalOf(el);
        if (!signal) return null;
        return wanted === "identity"
          ? identityKey(el, signal, tag === "SELECT" || !!el.options)
          : cardKey(signal);
      }
      function optionsOf(select) {
        try {
          return Array.from(select.options || []);
        } catch {
          return [];
        }
      }
      function monthTargets(value) {
        const raw = String(value).trim(),
          number = Number(raw),
          targets = new Set([raw, raw.padStart(2, "0"), raw.replace(/^0/, "")]);
        if (Number.isInteger(number) && number >= 1 && number <= 12) {
          targets.add(String(number));
          targets.add(String(number).padStart(2, "0"));
          for (const name of MONTHS[number - 1]) targets.add(name);
          targets.add(number + "月");
        }
        return [...targets].filter(Boolean);
      }
      function yearTargets(value) {
        const raw = String(value).trim();
        const digits = raw.match(/\d{2,4}/)?.[0] || raw;
        const targets = new Set([raw, digits]);
        if (digits.length === 2) targets.add("20" + digits);
        if (digits.length === 4) targets.add(digits.slice(-2));
        return [...targets].filter(Boolean);
      }
      function countryTargets(value) {
        const raw = String(value).trim(),
          upper = raw.toUpperCase(),
          targets = new Set([raw, upper]);
        const name = COUNTRY_NAMES[upper];
        if (name) {
          targets.add(name);
          for (const [code, candidate] of Object.entries(COUNTRY_NAMES))
            if (candidate === name && code.length === 2) targets.add(code);
        }
        const code = COUNTRY_CODES[raw.toLowerCase()];
        if (code) {
          targets.add(code);
          if (COUNTRY_NAMES[code]) targets.add(COUNTRY_NAMES[code]);
        }
        if (upper === "US") {
          targets.add("usa");
          targets.add("united states of america");
          targets.add("u.s.");
          targets.add("u.s.a.");
        }
        return [...targets].filter(Boolean);
      }
      function stateTargets(value) {
        const raw = String(value).trim(),
          upper = raw.toUpperCase(),
          targets = new Set([raw, upper]);
        if (STATES[upper]) targets.add(STATES[upper]);
        const code = STATE_CODES[raw.toLowerCase()];
        if (code) targets.add(code);
        return [...targets].filter(Boolean);
      }
      function optionMatch(select, value, field) {
        const raw = String(value == null ? "" : value).trim();
        const options = optionsOf(select);
        if (!options.length) return null;
        if (!raw) {
          const fallback =
            options.find((option) => option.defaultSelected) || options[0];
          return fallback ? String(fallback.value) : "";
        }
        let targets;
        if (field === "exp_month" || field === "birth_month")
          targets = monthTargets(raw);
        else if (field === "exp_year" || field === "birth_year")
          targets = yearTargets(raw);
        else if (field === "country_code" || field === "country_name")
          targets = countryTargets(raw);
        else if (field === "state") targets = stateTargets(raw);
        else targets = [raw];
        const lowered = targets.map((target) => String(target).toLowerCase());
        const usable = options.filter(
          (option) =>
            !option.disabled &&
            String(option.value == null ? "" : option.value).trim() !== "",
        );
        const exactValue = usable.find((option) =>
          lowered.includes(String(option.value).trim().toLowerCase()),
        );
        if (exactValue) return String(exactValue.value);
        const exactText = usable.find((option) =>
          lowered.includes(String(option.text || "").trim().toLowerCase()),
        );
        if (exactText) return String(exactText.value);
        for (const target of targets) {
          const number = Number(String(target).trim());
          if (!Number.isFinite(number)) continue;
          const numeric = usable.find(
            (option) =>
              String(option.value).trim() !== "" &&
              Number(String(option.value).trim()) === number,
          );
          if (numeric) return String(numeric.value);
        }
        for (const option of usable) {
          const text = String(option.text || "").trim().toLowerCase();
          const optionValue = String(option.value).trim().toLowerCase();
          for (const target of lowered) {
            if (!target) continue;
            if (
              text === target ||
              optionValue === target ||
              text.startsWith(target + " ") ||
              text.startsWith(target + "-") ||
              text.includes(target)
            )
              return String(option.value);
          }
        }
        return null;
      }
      function setControl(el, value, field) {
        if (!el || !eligible(el)) return false;
        const tag = String(el.tagName || "").toUpperCase();
        if (tag === "SELECT" || el.options) {
          const matched = optionMatch(el, value, field);
          if (matched === null) return false;
          const options = optionsOf(el);
          const index = options.findIndex(
            (option) => String(option.value) === matched,
          );
          if (index >= 0) {
            try {
              for (const option of options)
                option.selected = String(option.value) === matched;
            } catch {}
          }
          try {
            const descriptor = Object.getOwnPropertyDescriptor(
              HTMLSelectElement.prototype,
              "value",
            );
            if (descriptor && descriptor.set) descriptor.set.call(el, matched);
            else el.value = matched;
          } catch {
            el.value = matched;
          }
          el.dispatchEvent(new Event("input", { bubbles: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
          return true;
        }
        const proto =
          tag === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        try {
          const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
          if (descriptor && descriptor.set) descriptor.set.call(el, value);
          else el.value = value;
        } catch {
          el.value = value;
        }
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      }
      const source = { ...data };
      const values = {};
      let fullName = source.full_name || "";
      if (!fullName)
        fullName = [
          source.title,
          source.first_name,
          source.middle_name,
          source.last_name,
          source.suffix,
        ]
          .filter(Boolean)
          .join(" ");
      let first = source.first_name || "",
        middle = source.middle_name || "",
        last = source.last_name || "";
      if ((!first || !last) && source.full_name) {
        const parts = source.full_name.trim().split(/\s+/).filter(Boolean);
        if (parts.length === 1) {
          first = first || parts[0];
        } else {
          first = first || parts[0];
          last = last || parts.at(-1);
          if (!middle && parts.length > 2) middle = parts.slice(1, -1).join(" ");
        }
      }
      let countryCode = source.country_code || "";
      let countryName = source.country_name || "";
      if (!countryCode && countryName)
        countryCode = COUNTRY_CODES[countryName.trim().toLowerCase()] || "";
      if (!countryName && countryCode)
        countryName = COUNTRY_NAMES[countryCode.trim().toUpperCase()] || "";
      let birthYear = source.birth_year || "",
        birthMonth = source.birth_month || "",
        birthDay = source.birth_day || "",
        birthDate = source.birth_date || "";
      if (!birthDate && (birthYear || birthMonth || birthDay))
        birthDate = [birthYear, birthMonth.padStart(2, "0"), birthDay.padStart(2, "0")]
          .filter(Boolean)
          .join("-");
      if (birthDate && (!birthYear || !birthMonth || !birthDay)) {
        const match = /^(\d{4})-(\d{1,2})-(\d{1,2})/.exec(birthDate);
        if (match) {
          birthYear = birthYear || match[1];
          birthMonth = birthMonth || match[2];
          birthDay = birthDay || match[3];
        }
      }
      let expMonth = source.exp_month || "",
        expYear = source.exp_year || "",
        expRaw = source.exp || "";
      if ((!expMonth || !expYear) && expRaw) {
        const match = /(\d{1,2})\s*[/-]?\s*(\d{2,4})/.exec(expRaw);
        if (match) {
          expMonth = expMonth || match[1];
          expYear = expYear || match[2];
        }
      }
      if (expMonth) expMonth = String(expMonth).padStart(2, "0");
      if (expYear) {
        expYear = String(expYear);
        if (expYear.length === 2) expYear = "20" + expYear;
      }
      let cardholder =
        source.cardholder_name ||
        [source.given_name, source.additional_name, source.family_name]
          .filter(Boolean)
          .join(" ");
      let given = source.given_name || "",
        family = source.family_name || "";
      if ((!given || !family) && source.cardholder_name) {
        const parts = source.cardholder_name.trim().split(/\s+/).filter(Boolean);
        if (parts.length === 1) given = given || parts[0];
        else {
          given = given || parts[0];
          family = family || parts.at(-1);
        }
      }
      Object.assign(values, {
        full_name: fullName,
        first_name: first,
        middle_name: middle,
        last_name: last,
        title: source.title || "",
        suffix: source.suffix || "",
        company: source.company || "",
        job_title: source.job_title || "",
        street_address: source.street_address || "",
        address_line1: source.address_line1 || "",
        address_line2: source.address_line2 || "",
        address_line3: source.address_line3 || "",
        city: source.city || "",
        state: source.state || "",
        district: source.district || "",
        postal_code: source.postal_code || "",
        country_code: countryCode,
        country_name: countryName,
        phone: source.phone || "",
        phone_country_code: source.phone_country_code || "",
        email: source.email || "",
        birth_date: birthDate,
        birth_year: birthYear,
        birth_month: birthMonth,
        birth_day: birthDay,
        cardholder_name: cardholder,
        given_name: given,
        additional_name: source.additional_name || "",
        family_name: family,
        number: source.number || "",
        exp_month: expMonth,
        exp_year: expYear,
        cvv: source.cvv || "",
        type: source.type || "",
      });
      const fields = [];
      for (const el of deepAll(document, "input,select,textarea")) {
        const field = classify(el, category);
        if (field && !fields.some((entry) => entry.element === el))
          fields.push({ element: el, field });
      }
      if (!fields.length) return false;
      let filled = 0;
      for (const { element, field } of fields) {
        if (Date.now() >= expiresAt || location.origin !== expectedOrigin)
          return false;
        if (!element.isConnected) continue;
        let value = values[field];
        if (field === "exp" && (expMonth || expYear)) {
          const placeholder = String(element.placeholder || "");
          const maxLength = Number(element.maxLength);
          const month = expMonth || "01",
            year = expYear || "";
          if (maxLength === 7 || /yyyy/i.test(placeholder))
            value = month + "/" + year;
          else if (maxLength === 4 && !/\//.test(placeholder))
            value = month + (year ? year.slice(-2) : "");
          else value = month + "/" + (year ? year.slice(-2) : "");
        }
        if (field === "number" && typeof value === "string")
          value = value.replace(/[ -]/g, "");
        if (value === undefined || value === null || value === "") continue;
        if (setControl(element, String(value), field)) filled++;
      }
      return filled > 0;
    } catch {
      return false;
    }
  }
  function otpSignalText(el) {
    return [
      el.name,
      el.id,
      el.placeholder,
      el.getAttribute && el.getAttribute("aria-label"),
      el.getAttribute && el.getAttribute("title"),
      associatedLabel(el),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  }
  function otpInput(el) {
    if (!el) return false;
    let raw = "";
    try {
      raw = (el.getAttribute && el.getAttribute("autocomplete")) || "";
    } catch {}
    if (!raw && typeof el.autocomplete === "string") raw = el.autocomplete;
    if (
      String(raw)
        .toLowerCase()
        .split(/\s+/)
        .includes("one-time-code")
    )
      return true;
    const signal = otpSignalText(el);
    if (!signal) return false;
    if (/password|username|user.?name|card|credit|cc.?|cvv|search/i.test(signal))
      return false;
    return /(one.?time.?code|totp|otp|2fa|mfa|verification.?code|verification.?token|authenticator|passcode|验证码|动态码|短信验证码)/i.test(
      signal,
    );
  }
  function containerSignal(el) {
    const pieces = [];
    let node = el;
    for (let depth = 0; node && depth < 4; depth++) {
      if (node.nodeType === 1) {
        if (node.getAttribute) {
          for (const name of ["aria-label", "id", "class", "name"])
            pieces.push(node.getAttribute(name) || "");
        }
        if (typeof node.closest === "function") {
          const group = node.closest("fieldset,[role='group'],form");
          if (group && group !== node) {
            pieces.push(group.getAttribute?.("aria-label") || "");
            try {
              pieces.push(group.querySelector("legend")?.textContent || "");
            } catch {}
          }
        }
      }
      const parent = node.parentElement;
      if (parent) {
        node = parent;
        continue;
      }
      const root =
        typeof node.getRootNode === "function" ? node.getRootNode() : null;
      node = root && root !== node && root.host ? root.host : null;
    }
    return pieces.join(" ").toLowerCase();
  }
  function splitGroupValid(group, container) {
    if (![6, 8].includes(group.length)) return false;
    if (
      group.some(
        (el) =>
          String(el.type || "").toLowerCase() === "hidden" ||
          !["text", "tel", "number", "password"].includes(
            String(el.type || "").toLowerCase(),
          ),
      )
    )
      return false;
    if (group.some(otpInput)) return true;
    const marker = containerSignal(container || group[0]);
    if (/(otp|totp|2fa|mfa|code|digit|pin|verify|verification|token|passcode|验证码|动态码)/i.test(marker))
      return true;
    return group.every((el) => {
      const mode = String(el.getAttribute?.("inputmode") || "").toLowerCase();
      const pattern = String(el.getAttribute?.("pattern") || "");
      const type = String(el.type || "").toLowerCase();
      return (
        mode === "numeric" ||
        /\[0-9\]|\\d/.test(pattern) ||
        type === "tel" ||
        type === "number"
      );
    });
  }
  function findOTPTargets(root) {
    const scope =
      root && typeof root.querySelectorAll === "function"
        ? root
        : typeof document !== "undefined"
          ? document
          : null;
    if (!scope) return null;
    const inputs = queryAllDeep(scope, "input").filter(eligibleControl);
    const eligibleTypes = inputs.filter((el) =>
      ["text", "tel", "number", "password"].includes(
        String(el.type || "").toLowerCase(),
      ),
    );
    const splitInputs = eligibleTypes.filter(
      (el) => Number(el.maxLength) === 1 || el.getAttribute?.("maxlength") === "1",
    );
    const groups = new Map();
    for (const el of splitInputs) {
      let container = null;
      try {
        container = el.form || (el.closest && el.closest("form")) || null;
      } catch {}
      if (!container) {
        try {
          container = el.parentElement || el.getRootNode?.() || scope;
        } catch {
          container = scope;
        }
      }
      if (!groups.has(container)) groups.set(container, []);
      groups.get(container).push(el);
    }
    const validGroups = [...groups.values()].filter(
      (group) =>
        group.length === 6 ||
        group.length === 8
          ? splitGroupValid(group, group[0].form || group[0])
          : false,
    );
    if (validGroups.length === 1) {
      const group = validGroups[0];
      return {
        kind: "split",
        inputs: group,
        form:
          group[0].form ||
          (group[0].closest && group[0].closest("form")) ||
          null,
      };
    }
    if (validGroups.length > 1) return null;
    const singles = eligibleTypes.filter(
      (el) =>
        Number(el.maxLength) !== 1 &&
        (Number(el.maxLength) < 0 || Number(el.maxLength) >= 6) &&
        otpInput(el),
    );
    if (singles.length === 1) {
      const input = singles[0];
      return {
        kind: "single",
        inputs: [input],
        form: input.form || (input.closest && input.closest("form")) || null,
      };
    }
    return null;
  }
  // Serialized into the target frame's isolated world. Detects either one
  // one-time-code input or a 6/8 box split group; fill length must match.
  function otpDocument(expected, mode, code, timing, allowSubframe) {
    "use strict";
    try {
      function frameAllowed() {
        if (window === window.top) return true;
        if (allowSubframe !== true) return false;
        try {
          return (
            window.top.location.origin === location.origin &&
            location.origin !== "null"
          );
        } catch {
          return false;
        }
      }
      if (
        !frameAllowed() ||
        (location.protocol !== undefined && location.protocol !== "https:") ||
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
        timing.top !== (window === window.top) ||
        timing.origin !== expected ||
        !alive(timing) ||
        !inBudget()
      )
        return false;
      function deepAll(root, selector) {
        const out = [];
        let budget = 5000;
        function walk(node, depth) {
          if (!node || depth > 8 || budget <= 0) return;
          let matches;
          try {
            matches = node.querySelectorAll(selector);
          } catch {
            return;
          }
          for (const el of matches) {
            out.push(el);
            if (--budget <= 0) return;
          }
          let all;
          try {
            all = node.querySelectorAll("*");
          } catch {
            return;
          }
          for (const el of all)
            if (el && el.shadowRoot && el.shadowRoot.mode === "open")
              walk(el.shadowRoot, depth + 1);
        }
        walk(root, 0);
        return out;
      }
      function rootNode(el) {
        try {
          const root = el.getRootNode && el.getRootNode();
          return root && root.host ? root : null;
        } catch {
          return null;
        }
      }
      function eligible(input) {
        if (
          !input ||
          input.isConnected === false ||
          input.disabled ||
          input.readOnly ||
          String(input.type || "").toLowerCase() === "hidden" ||
          input.hidden ||
          !["text", "tel", "number", "password"].includes(
            String(input.type || "").toLowerCase(),
          ) ||
          input.matches(":disabled") ||
          input.closest('[hidden],[inert],[aria-hidden="true"]')
        )
          return false;
        for (let node = input; node instanceof Element; ) {
          const style = getComputedStyle(node);
          if (
            style.display === "none" ||
            style.visibility !== "visible" ||
            Number(style.opacity) === 0
          )
            return false;
          let next = node.parentElement;
          if (!next) {
            const root = rootNode(node);
            next = root ? root.host : null;
          }
          node = next;
        }
        const rect = input.getBoundingClientRect();
        return (
          input.getClientRects().length > 0 && rect.width > 0 && rect.height > 0
        );
      }
      function labelText(el) {
        const pieces = [];
        try {
          if (el.labels && el.labels.length)
            for (const label of el.labels) pieces.push(label.textContent || "");
          if (el.id && typeof document.querySelector === "function") {
            const escaped =
              typeof CSS !== "undefined" && CSS.escape
                ? CSS.escape(el.id)
                : String(el.id).replace(/["\\]/g, "\\$&");
            const label = document.querySelector('label[for="' + escaped + '"]');
            if (label) pieces.push(label.textContent || "");
          }
          if (typeof el.closest === "function") {
            const label = el.closest("label");
            if (label) pieces.push(label.textContent || "");
          }
        } catch {}
        return pieces.join(" ");
      }
      function otpSignal(el) {
        return [
          el.name,
          el.id,
          el.placeholder,
          el.getAttribute && el.getAttribute("aria-label"),
          el.getAttribute && el.getAttribute("title"),
          labelText(el),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
      }
      function isOTP(el) {
        let raw = "";
        try {
          raw = (el.getAttribute && el.getAttribute("autocomplete")) || "";
        } catch {}
        if (!raw && typeof el.autocomplete === "string") raw = el.autocomplete;
        if (
          String(raw)
            .toLowerCase()
            .split(/\s+/)
            .includes("one-time-code")
        )
          return true;
        const signal = otpSignal(el);
        if (!signal) return false;
        if (/password|username|user.?name|card|credit|cc.?|cvv|search/i.test(signal))
          return false;
        return /(one.?time.?code|totp|otp|2fa|mfa|verification.?code|verification.?token|authenticator|passcode|验证码|动态码|短信验证码)/i.test(
          signal,
        );
      }
      function containerSignal(el) {
        const pieces = [];
        let node = el;
        for (let depth = 0; node && depth < 4; depth++) {
          if (node.nodeType === 1 && node.getAttribute)
            for (const name of ["aria-label", "id", "class", "name"])
              pieces.push(node.getAttribute(name) || "");
          const parent = node.parentElement;
          if (parent) {
            node = parent;
            continue;
          }
          const root = rootNode(node);
          node = root ? root.host : null;
        }
        return pieces.join(" ").toLowerCase();
      }
      function groupValid(group) {
        if (![6, 8].includes(group.length)) return false;
        if (group.some((el) => !eligible(el))) return false;
        if (group.some(isOTP)) return true;
        if (
          /(otp|totp|2fa|mfa|code|digit|pin|verify|verification|token|passcode|验证码|动态码)/i.test(
            containerSignal(group[0]),
          )
        )
          return true;
        return group.every((el) => {
          const mode = String(
            el.getAttribute?.("inputmode") || "",
          ).toLowerCase();
          const pattern = String(el.getAttribute?.("pattern") || "");
          const type = String(el.type || "").toLowerCase();
          return (
            mode === "numeric" ||
            /\[0-9\]|\\d/.test(pattern) ||
            type === "tel" ||
            type === "number"
          );
        });
      }
      function detect() {
        const all = deepAll(document, "input").filter(eligible);
        const suits = all.filter((el) =>
          ["text", "tel", "number", "password"].includes(
            String(el.type || "").toLowerCase(),
          ),
        );
        const boxes = suits.filter(
          (el) =>
            Number(el.maxLength) === 1 ||
            el.getAttribute?.("maxlength") === "1",
        );
        const groups = new Map();
        for (const el of boxes) {
          let container = null;
          try {
            container = el.form || (el.closest && el.closest("form")) || null;
          } catch {}
          if (!container) container = el.parentElement || rootNode(el) || document;
          if (!groups.has(container)) groups.set(container, []);
          groups.get(container).push(el);
        }
        const valid = [...groups.values()].filter((group) => groupValid(group));
        if (valid.length === 1)
          return {
            kind: "split",
            inputs: valid[0],
            form:
              valid[0][0].form ||
              (valid[0][0].closest && valid[0][0].closest("form")) ||
              null,
          };
        if (valid.length > 1) return null;
        const singles = suits.filter(
          (el) =>
            Number(el.maxLength) !== 1 &&
            (Number(el.maxLength) < 0 || Number(el.maxLength) >= 6) &&
            isOTP(el),
        );
        if (singles.length === 1)
          return {
            kind: "single",
            inputs: singles,
            form:
              singles[0].form ||
              (singles[0].closest && singles[0].closest("form")) ||
              null,
          };
        return null;
      }
      function sameAction(raw) {
        const url = new URL(raw || location.href, document.baseURI);
        return (
          url.protocol === "https:" &&
          url.origin === expected &&
          !url.username &&
          !url.password
        );
      }
      function validTarget(target) {
        if (!target || !target.inputs.length || window !== window.top && false)
          return false;
        if (location.origin !== expected) return false;
        if (target.form) {
          if (
            !target.form.isConnected ||
            (target.form.ownerDocument && target.form.ownerDocument !== document) ||
            !sameAction(
              typeof target.form.getAttribute === "function"
                ? target.form.getAttribute("action")
                : null,
            )
          )
            return false;
          for (const submitter of deepAll(
            document,
            "button[formaction],input[formaction]",
          ))
            if (
              submitter.form === target.form &&
              !sameAction(submitter.getAttribute("formaction"))
            )
              return false;
        }
        if (target.kind === "split") {
          if (![6, 8].includes(target.inputs.length)) return false;
          if (target.inputs.some((el) => !el.isConnected || !eligible(el)))
            return false;
          return true;
        }
        return target.inputs.length === 1 && eligible(target.inputs[0]);
      }
      const target = detect();
      if (!target || !validTarget(target)) return false;
      if (mode === "probe") {
        const sample = clock();
        return alive(sample)
          ? { origin: expected, top: window === window.top, ...sample }
          : false;
      }
      if (target.kind === "split" && target.inputs.length !== code.length)
        return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      ).set;
      function fireInput(el, type, init) {
        try {
          el.dispatchEvent(new InputEvent(type, init));
        } catch {
          el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
        }
      }
      function fireKey(el, type, key) {
        try {
          el.dispatchEvent(
            new KeyboardEvent(type, {
              key,
              code: "Digit" + key,
              bubbles: true,
              cancelable: true,
              composed: true,
            }),
          );
        } catch {
          el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
        }
      }
      // No event or await separates the final checks and the writes below.
      if (!validTarget(target) || !inBudget()) return false;
      if (target.kind === "single") {
        const input = target.inputs[0];
        setter.call(input, code);
        code = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
        return true;
      }
      for (let index = 0; index < target.inputs.length; index++) {
        const el = target.inputs[index],
          char = code[index];
        if (!el.isConnected || !eligible(el)) return false;
        if (Date.now() >= timing.wall + 1500) return false;
        el.focus();
        fireKey(el, "keydown", char);
        fireInput(el, "beforeinput", {
          data: char,
          inputType: "insertText",
          bubbles: true,
          cancelable: true,
          composed: true,
        });
        if (el.value !== char) setter.call(el, char);
        fireInput(el, "input", {
          data: char,
          inputType: "insertText",
          bubbles: true,
          cancelable: true,
          composed: true,
        });
        el.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
        fireKey(el, "keyup", char);
      }
      code = "";
      return true;
    } catch {
      return false;
    }
  }
  const fillIdentityDocument = autofillDocument;
  const fillCardDocument = autofillDocument;
  return {
    originFromURL,
    siteKey,
    sameSite,
    validSender,
    sameContext,
    validResponse,
    classifyField,
    inspectAutofillFields,
    queryAllDeep,
    eventInputTarget,
    eligibleControl,
    selectOptionMatch,
    otpInput,
    findOTPTargets,
    probe,
    fillDocument,
    fillIdentityDocument,
    fillCardDocument,
    otpDocument,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
