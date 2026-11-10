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
  // Paste-time protection. A Secret Key (LL1-, LLR2- recovery material) is only
  // ever entered inside the Locklark app, so pasting one into a web page is
  // always refused by default. The phishing warning is narrower: it needs
  // positive knowledge that this origin has no saved login (siteLinked ===
  // false). An unknown site state, a locked vault or a disconnected host must
  // never block or warn on a paste.
  const SECRET_KEY_PATTERNS = Object.freeze([
    /^LL1-[A-Z2-7]{26}$/,
    /^LLR2-[A-Z2-7]{52}$/,
    /^LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}$/,
  ]);
  const SECRET_KEY_MIN_LENGTH = 30;
  const SECRET_KEY_MAX_LENGTH = 110;
  function looksLikeLocklarkSecret(text) {
    if (typeof text !== "string") return false;
    const value = text.trim();
    if (
      value.length < SECRET_KEY_MIN_LENGTH ||
      value.length > SECRET_KEY_MAX_LENGTH
    )
      return false;
    return SECRET_KEY_PATTERNS.some((pattern) => pattern.test(value));
  }
  function pasteWarning(raw) {
    if (!raw || typeof raw !== "object" || raw.enabled === false) return "";
    const text = typeof raw.text === "string" ? raw.text : "";
    if (!text.trim()) return "";
    if (looksLikeLocklarkSecret(text)) return "secret-key";
    if (raw.isPasswordField === true && raw.siteLinked === false)
      return "phishing";
    return "";
  }
  // Two-factor setup capture. A page may render an otpauth:// QR code during
  // setup; the content script decodes it with the browser's BarcodeDetector and
  // offers to save the configuration to an existing login after an explicit
  // click. Validation mirrors the native totp parser: TOTP only, the five
  // supported parameters, a canonical-enough Base32 secret, SHA1/256/512,
  // 6/8 digits and a 1-3600 second period. The returned object carries display
  // metadata only and never the secret.
  const OTPAUTH_MAX_LENGTH = 1024;
  const OTPAUTH_SECRET_MIN_BYTES = 16;
  const OTPAUTH_SECRET_MAX_BYTES = 64;
  const OTPAUTH_PARAMS = new Set([
    "secret",
    "issuer",
    "algorithm",
    "digits",
    "period",
  ]);
  function otpAuthText(value) {
    return (
      typeof value === "string" &&
      value.length >= 8 &&
      value.length <= OTPAUTH_MAX_LENGTH &&
      value.isWellFormed()
    );
  }
  // Mirrors the native label rule: non-empty, at most 256 characters, no
  // control characters and no path separators.
  function boundedLabel(value, max) {
    if (typeof value !== "string") return "";
    const text = value.trim();
    if (text.length === 0 || text.length > max) return "";
    if (text.includes("/") || text.includes("\\")) return "";
    for (const character of text) {
      const code = character.codePointAt(0);
      if (code < 32 || (code >= 0x7f && code < 0xa0)) return "";
    }
    return text;
  }
  // Decoded byte count for an unpadded Base32 string; null when the length
  // cannot decode at all (length mod 8 == 1, 3 or 6).
  function base32DecodedLength(characters) {
    const remainder = characters % 8;
    if (![0, 2, 4, 5, 7].includes(remainder)) return null;
    return Math.floor((characters * 5) / 8);
  }
  // Returns {issuer, account, label, digits, period, algorithm} or null.
  function parseOTPAuthTOTP(value) {
    if (!otpAuthText(value)) return null;
    // No surrounding or embedded whitespace: the native parser treats any
    // such byte as part of the seed or label and refuses it.
    if (value !== value.trim() || value.includes("#") || /\s/.test(value))
      return null;
    const raw = value;
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return null;
    }
    if (
      parsed.protocol !== "otpauth:" ||
      parsed.hostname.toLowerCase() !== "totp" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.hash !== ""
    )
      return null;
    const query = parsed.search.replace(/^\?/, "");
    if (!query || query.includes(";")) return null;
    const params = new Map();
    for (const [key, field] of parsed.searchParams) {
      if (!OTPAUTH_PARAMS.has(key) || params.has(key) || field === "")
        return null;
      params.set(key, field);
    }
    const secret = (params.get("secret") || "").toUpperCase();
    const padding = /(=*)$/.exec(secret)?.[1] || "";
    const characters = secret.length - padding.length;
    if (
      !/^[A-Z2-7]+=*$/.test(secret) ||
      (padding && secret.length % 8 !== 0)
    )
      return null;
    const bytes = base32DecodedLength(characters);
    if (
      bytes === null ||
      bytes < OTPAUTH_SECRET_MIN_BYTES ||
      bytes > OTPAUTH_SECRET_MAX_BYTES ||
      secret.length > 104
    )
      return null;
    const digits = params.has("digits") ? params.get("digits") : "6";
    if (digits !== "6" && digits !== "8") return null;
    const period = params.has("period") ? params.get("period") : "30";
    if (!/^[1-9][0-9]{0,3}$/.test(period)) return null;
    const periodSeconds = Number(period);
    if (periodSeconds < 1 || periodSeconds > 3600) return null;
    const algorithm = (params.get("algorithm") || "SHA1").toUpperCase();
    if (!["SHA1", "SHA256", "SHA512"].includes(algorithm)) return null;
    let label = parsed.pathname.replace(/^\//, "");
    try {
      label = decodeURIComponent(label);
    } catch {
      return null;
    }
    if ((label.match(/:/g) || []).length > 1) return null;
    let accountIssuer = "";
    let account = label;
    const separator = label.indexOf(":");
    if (separator >= 0) {
      accountIssuer = label.slice(0, separator);
      account = label.slice(separator + 1);
    }
    const declaredRaw = params.get("issuer") || "";
    const declaredIssuer = declaredRaw ? boundedLabel(declaredRaw, 256) : "";
    if (declaredRaw && !declaredIssuer) return null;
    const labelIssuer = accountIssuer
      ? boundedLabel(accountIssuer, 256)
      : "";
    if (accountIssuer && !labelIssuer) return null;
    if (declaredIssuer && labelIssuer && declaredIssuer !== labelIssuer)
      return null;
    const issuer = declaredIssuer || labelIssuer;
    const accountLabel = account ? boundedLabel(account, 256) : "";
    if (account && !accountLabel) return null;
    if (!issuer && !accountLabel) return null;
    const display = issuer
      ? accountLabel && accountLabel !== issuer
        ? issuer + " · " + accountLabel
        : issuer
      : accountLabel;
    return {
      issuer,
      account: accountLabel,
      label: display,
      digits: Number(digits),
      period: periodSeconds,
      algorithm,
    };
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
  const WATCHTOWER_FLAGS = Object.freeze([
    "empty",
    "common-pattern",
    "short",
    "low-variety",
    "weak",
    "reused",
    "unsecured-http",
    "totp-not-stored",
    "passkey-not-stored",
    "expiring-soon",
    "expired",
    "vulnerable",
  ]);
  const STRENGTH_CATEGORIES = Object.freeze([
    "terrible",
    "weak",
    "fair",
    "good",
    "very-good",
    "excellent",
    "fantastic",
  ]);
  const WATCHTOWER_COUNTS = Object.freeze([
    "vulnerable",
    "reused",
    "weak",
    "unsecured_http",
    "totp_not_stored",
    "expiring",
  ]);
  const WATCHTOWER_OPTIONAL_COUNTS = Object.freeze(["passkey_not_stored"]);
  const WATCHTOWER_REPORT_KEYS = Object.freeze([
    "profile",
    "hibp_checked",
    "hibp_error",
    "overall_score",
    "checked",
    "skipped",
    "counts",
    "site",
    "site_findings",
    "findings",
  ]);
  const WATCHTOWER_FINDING_KEYS = Object.freeze([
    "id",
    "revision",
    "title",
    "origin",
    "flags",
    "strength_score",
    "strength_category",
    "reuse_count",
    "breach_count",
  ]);
  const CANDIDATE_KEYS = Object.freeze([
    "id",
    "revision",
    "title",
    "state",
    "category",
    "subtitle",
    "watchtower_flags",
    "strength_score",
    "strength_category",
    "reuse_count",
    "breach_count",
  ]);
  const MAX_WATCHTOWER_FINDINGS = 5000;
  const MAX_WATCHTOWER_COUNT = 1000000;
  function plainObject(value) {
    return !!value && typeof value === "object" && !Array.isArray(value);
  }
  function boundedInteger(value, min, max) {
    return (
      Number.isSafeInteger(value) && value >= min && value <= max
    );
  }
  function knownKeysOnly(value, allowed) {
    return Object.keys(value).every((key) => allowed.includes(key));
  }
  function validOriginHost(host) {
    if (!host || host.length > 253) return false;
    if (host.startsWith("[") && host.endsWith("]"))
      return /^\[[0-9a-f:.]+\]$/i.test(host);
    return host.split(".").every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );
  }
  // Canonical web origin only: scheme, host, optional port, no path/query/
  // fragment/credentials. Findings may carry an http origin; opening tabs is
  // restricted separately to https.
  function validWebOrigin(raw) {
    if (
      typeof raw !== "string" ||
      raw.length > 2048 ||
      /[\\\x00-\x20\x7f-\uffff]/u.test(raw)
    )
      return false;
    let u;
    try {
      u = new URL(raw);
    } catch {
      return false;
    }
    return (
      (u.protocol === "https:" || u.protocol === "http:") &&
      !u.username &&
      !u.password &&
      u.origin !== "null" &&
      u.origin === raw &&
      validOriginHost(u.hostname)
    );
  }
  function validHTTPSOrigin(raw) {
    return (
      typeof raw === "string" &&
      raw.startsWith("https://") &&
      validWebOrigin(raw)
    );
  }
  function siteFromURL(raw) {
    if (
      typeof raw !== "string" ||
      raw.length > 8192 ||
      /[\\\x00-\x20\x7f]/u.test(raw)
    )
      return null;
    let u;
    try {
      u = new URL(raw);
    } catch {
      return null;
    }
    if (
      (u.protocol !== "https:" && u.protocol !== "http:") ||
      u.username ||
      u.password ||
      u.origin === "null" ||
      !validOriginHost(u.hostname)
    )
      return null;
    const host = u.hostname.toLowerCase();
    // Match the native rule: plain-text HTTP is only tolerated on loopback.
    const loopback =
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host === "[::1]";
    return {
      origin: u.origin,
      unsecured: u.protocol === "http:" && !loopback,
    };
  }
  function validWatchtowerFlags(flags, allowEmpty = true) {
    if (!Array.isArray(flags) || flags.length > WATCHTOWER_FLAGS.length)
      return false;
    if (!allowEmpty && flags.length === 0) return false;
    const seen = new Set();
    for (const flag of flags) {
      if (typeof flag !== "string" || !WATCHTOWER_FLAGS.includes(flag))
        return false;
      if (seen.has(flag)) return false;
      seen.add(flag);
    }
    return true;
  }
  function validWatchtowerCounts(counts) {
    if (!plainObject(counts)) return false;
    if (
      !knownKeysOnly(counts, [
        ...WATCHTOWER_COUNTS,
        ...WATCHTOWER_OPTIONAL_COUNTS,
      ])
    )
      return false;
    for (const key of WATCHTOWER_COUNTS)
      if (!boundedInteger(counts[key], 0, MAX_WATCHTOWER_COUNT)) return false;
    if (
      Object.hasOwn(counts, "passkey_not_stored") &&
      !boundedInteger(counts.passkey_not_stored, 0, MAX_WATCHTOWER_COUNT)
    )
      return false;
    return true;
  }
  function validWatchtowerFinding(finding) {
    if (!plainObject(finding)) return false;
    if (!knownKeysOnly(finding, WATCHTOWER_FINDING_KEYS)) return false;
    if (
      !/^[a-f0-9]{32}$/.test(finding.id || "") ||
      !/^[a-f0-9]{64}$/.test(finding.revision || "") ||
      typeof finding.title !== "string" ||
      finding.title.length > 1024 ||
      !validWatchtowerFlags(finding.flags) ||
      !boundedInteger(finding.strength_score, 0, 100) ||
      !STRENGTH_CATEGORIES.includes(finding.strength_category) ||
      !boundedInteger(finding.reuse_count, 0, MAX_WATCHTOWER_COUNT) ||
      !boundedInteger(finding.breach_count, 0, MAX_WATCHTOWER_COUNT)
    )
      return false;
    if (
      Object.hasOwn(finding, "origin") &&
      (typeof finding.origin !== "string" ||
        !validWebOrigin(finding.origin))
    )
      return false;
    return true;
  }
  function validWatchtower(report) {
    if (!plainObject(report)) return false;
    if (!knownKeysOnly(report, WATCHTOWER_REPORT_KEYS)) return false;
    if (
      report.profile !== "watchtower-v2" ||
      typeof report.hibp_checked !== "boolean" ||
      !boundedInteger(report.overall_score, 0, 100) ||
      !boundedInteger(report.checked, 0, MAX_WATCHTOWER_COUNT) ||
      (Object.hasOwn(report, "skipped") &&
        !boundedInteger(report.skipped, 0, MAX_WATCHTOWER_COUNT)) ||
      (Object.hasOwn(report, "hibp_error") &&
        report.hibp_error !== "unavailable") ||
      !validWatchtowerCounts(report.counts) ||
      !plainObject(report.site) ||
      !knownKeysOnly(report.site, ["origin", "unsecured_http"]) ||
      typeof report.site.unsecured_http !== "boolean" ||
      !Array.isArray(report.site_findings) ||
      !Array.isArray(report.findings) ||
      report.site_findings.length > MAX_WATCHTOWER_FINDINGS ||
      report.findings.length > MAX_WATCHTOWER_FINDINGS
    )
      return false;
    if (
      Object.hasOwn(report.site, "origin") &&
      !validHTTPSOrigin(report.site.origin)
    )
      return false;
    return (
      report.site_findings.every(validWatchtowerFinding) &&
      report.findings.every(validWatchtowerFinding)
    );
  }
  function validCandidate(row) {
    if (!plainObject(row)) return false;
    if (!knownKeysOnly(row, CANDIDATE_KEYS)) return false;
    if (
      !/^[a-f0-9]{32}$/.test(row.id || "") ||
      !/^[a-f0-9]{64}$/.test(row.revision || "") ||
      typeof row.title !== "string" ||
      row.title.length > 1024 ||
      row.state !== "active" ||
      !validCategory(row.category) ||
      (Object.hasOwn(row, "subtitle") &&
        (typeof row.subtitle !== "string" || row.subtitle.length > 1024))
    )
      return false;
    if (
      Object.hasOwn(row, "watchtower_flags") &&
      !validWatchtowerFlags(row.watchtower_flags)
    )
      return false;
    if (
      Object.hasOwn(row, "strength_score") &&
      !boundedInteger(row.strength_score, 0, 100)
    )
      return false;
    if (
      Object.hasOwn(row, "strength_category") &&
      !STRENGTH_CATEGORIES.includes(row.strength_category)
    )
      return false;
    for (const key of ["reuse_count", "breach_count"])
      if (
        Object.hasOwn(row, key) &&
        !boundedInteger(row[key], 0, MAX_WATCHTOWER_COUNT)
      )
        return false;
    return true;
  }
  function watchtowerFlagsForRow(row) {
    if (!plainObject(row) || !Array.isArray(row.watchtower_flags)) return [];
    return WATCHTOWER_FLAGS.filter((flag) =>
      row.watchtower_flags.includes(flag),
    );
  }
  const NATIVE_CATEGORY_ALIASES = Object.freeze({
    card: "credit_card",
    credit_card: "credit_card",
    "credit-card": "credit_card",
    note: "secure_note",
    secure_note: "secure_note",
    "secure-note": "secure_note",
    ssh: "ssh_key",
    ssh_key: "ssh_key",
    "ssh-key": "ssh_key",
  });
  function nativeCategory(raw) {
    const normalized = normalizeCategory(raw);
    if (!normalized) return "";
    return NATIVE_CATEGORY_ALIASES[normalized] || normalized;
  }
  function nativeFieldType(type) {
    const value = typeof type === "string" ? type.trim().toLowerCase() : "";
    if (value === "password" || value === "cvv" || value === "card_number")
      return "concealed";
    if (value === "multiline") return "text";
    return ["string", "text", "concealed", "email", "url", "otp", "totp", "date", "number", "phone"].includes(value)
      ? value
      : "text";
  }
  function nativeMatchMode(value) {
    return ["origin", "host", "regex", "never"].includes(value)
      ? value
      : "origin";
  }
  function stableFieldID(seed, used) {
    let hash = 2166136261;
    const text = String(seed || "field");
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    const base = "f" + (hash >>> 0).toString(16).padStart(8, "0");
    let id = base,
      suffix = 2;
    while (used.has(id)) id = base + "-" + suffix++;
    used.add(id);
    return id;
  }
  function nativeURLs(item) {
    const source = Array.isArray(item?.urls) ? item.urls : [];
    const urls = [];
    for (const entry of source.slice(0, 20)) {
      const raw = typeof entry === "string" ? entry : entry?.url;
      if (typeof raw !== "string" || !raw.trim()) continue;
      const value = raw.trim();
      if (value.length > 8192) continue;
      try {
        originFromURL(value);
      } catch {
        continue;
      }
      const out = { url: value, match_mode: "origin" };
      if (typeof entry === "object" && entry) {
        if (typeof entry.label === "string" && entry.label.trim())
          out.label = entry.label.trim().slice(0, 256);
        out.primary = entry.primary === true;
        out.match_mode = nativeMatchMode(entry.match_mode);
      }
      urls.push(out);
    }
    if (urls.length && !urls.some((url) => url.primary === true))
      urls[0].primary = true;
    return urls;
  }
  function nativeOriginalField(original, sectionID, fieldID) {
    if (!Array.isArray(original?.sections)) return null;
    for (const section of original.sections) {
      if (section?.id !== sectionID || !Array.isArray(section.fields)) continue;
      return section.fields.find((field) => field?.id === fieldID) || null;
    }
    return null;
  }
  function nativeOriginalFieldAny(original, fieldID) {
    if (!Array.isArray(original?.sections)) return null;
    for (const section of original.sections) {
      if (!Array.isArray(section?.fields)) continue;
      const found = section.fields.find((field) => field?.id === fieldID);
      if (found) return found;
    }
    return null;
  }
  function nativeSections(item, original, clearFields = new Set()) {
    const incoming = Array.isArray(item?.sections) ? item.sections : null;
    const legacyFields = Array.isArray(item?.fields) ? item.fields : [];
    if (!incoming && !legacyFields.length) return undefined;
    const sections = [];
    const byID = new Map();
    const used = new Set();
    const ensureSection = (id, title) => {
      const clean = typeof id === "string" && id ? id.slice(0, 128) : "custom-fields";
      let section = byID.get(clean);
      if (!section) {
        section = {
          id: clean,
          title: (title || "Custom fields").slice(0, 256),
          fields: [],
        };
        byID.set(clean, section);
        sections.push(section);
      }
      return section;
    };
    if (incoming) {
      for (const section of incoming.slice(0, 20)) {
        if (!section || typeof section !== "object") continue;
        ensureSection(section.id, section.title);
      }
    }
    const addField = (field, forcedSection) => {
      if (!field || typeof field !== "object") return;
      let sectionID =
        forcedSection ||
        (typeof field.section_id === "string" && field.section_id
          ? field.section_id
          : "custom-fields");
      // A legacy flat field that already lives in a supplied section keeps its
      // stable section instead of spawning a duplicate custom-fields entry.
      if (!forcedSection && incoming && typeof field.id === "string" && field.id)
        for (const candidate of sections)
          if (candidate.fields.some((entry) => entry.id === field.id)) {
            sectionID = candidate.id;
            break;
          }
      const section = ensureSection(
        sectionID,
        typeof field.section_title === "string" ? field.section_title : "Custom fields",
      );
      const label = String(field.label || "").trim().slice(0, 256);
      const rawValue = typeof field.value === "string" ? field.value.slice(0, 16384) : "";
      const declaredType = typeof field.type === "string" ? field.type.trim() : "";
      const id =
        typeof field.id === "string" &&
        /^[A-Za-z0-9_.:-]{1,128}$/.test(field.id) &&
        !field.id.startsWith("section:")
          ? field.id
          : stableFieldID(label || rawValue, used);
      if (!used.has(id)) used.add(id);
      const old =
        nativeOriginalField(original, section.id, id) ||
        nativeOriginalFieldAny(original, id);
      const oldConcealed =
        !!old &&
        (old.concealed === true ||
          old.has_value === true ||
          nativeFieldType(old.type) === "concealed");
      const concealed =
        field.concealed === true ||
        oldConcealed ||
        nativeFieldType(declaredType || (old ? old.type : "text")) === "concealed";
      const explicitClear = clearFields.has("section:" + section.id + ":" + id);
      const out = {
        id,
        label,
        type: nativeFieldType(declaredType || (old ? old.type : "text")),
      };
      if (concealed) out.concealed = true;
      const purpose =
        typeof field.purpose === "string" && field.purpose
          ? field.purpose
          : typeof old?.purpose === "string"
            ? old.purpose
            : "";
      if (purpose) out.purpose = purpose.slice(0, 128);
      // A masked placeholder is never a value. An untouched existing protected
      // field omits `value` so the host keeps it; only an explicit clear (or a
      // genuinely new value) replaces it.
      let value;
      if (explicitClear) value = "";
      else if (/^•+$/.test(rawValue)) value = undefined;
      else if (rawValue === "" && oldConcealed) value = undefined;
      else value = rawValue;
      if (value !== undefined) out.value = value;
      const index = section.fields.findIndex((entry) => entry.id === id);
      if (index >= 0) section.fields[index] = out;
      else section.fields.push(out);
    };
    if (incoming)
      for (const section of incoming.slice(0, 20)) {
        if (!section || typeof section !== "object" || !Array.isArray(section.fields))
          continue;
        for (const field of section.fields.slice(0, 100)) addField(field, section.id);
      }
    for (const field of legacyFields.slice(0, 100)) addField(field);
    const result = sections.filter((section) => section.fields.length);
    if (!result.length && !incoming) return undefined;
    return result;
  }
  function nativeCreditCard(item) {
    const source = item?.credit_card && typeof item.credit_card === "object" ? item.credit_card : item;
    if (!source || typeof source !== "object") return undefined;
    const card = {};
    const text = (key) =>
      typeof source[key] === "string" ? source[key].trim().slice(0, 256) : "";
    const name = text("cardholder_name") || text("cardholder");
    const brand = text("type") || text("brand");
    const expiry = text("expiry_date") || text("expiry");
    const validFrom = text("valid_from");
    const bank = text("issuing_bank");
    const number = typeof source.number === "string" ? source.number.trim() : typeof source.card_number === "string" ? source.card_number.trim() : "";
    const verification = typeof source.verification === "string" ? source.verification.trim() : typeof source.cvv === "string" ? source.cvv.trim() : "";
    const pin = typeof source.pin === "string" ? source.pin.trim() : "";
    if (name) card.cardholder_name = name;
    if (brand) card.type = brand;
    if (number) card.number = number.slice(0, 64);
    if (verification) card.verification = verification.slice(0, 32);
    if (expiry) card.expiry_date = expiry.slice(0, 32);
    if (validFrom) card.valid_from = validFrom.slice(0, 32);
    if (pin) card.pin = pin.slice(0, 32);
    if (bank) card.issuing_bank = bank.slice(0, 256);
    return Object.keys(card).length ? card : undefined;
  }
  function nativeIdentity(item) {
    const source = item?.identity && typeof item.identity === "object" ? item.identity : item;
    if (!source || typeof source !== "object") return undefined;
    const map = {
      first_name: "first_name", middle_name: "middle_name", last_name: "last_name",
      birth_date: "birth_date", company: "company", organization: "company",
      department: "department", job_title: "job_title", email: "email", phone: "phone",
      address1: "address_line1", address_line1: "address_line1", address2: "address_line2",
      address_line2: "address_line2", city: "city", state: "state",
      postal_code: "postal_code", country: "country", website: "website",
    };
    const out = {};
    for (const [key, target] of Object.entries(map)) {
      const value = source[key];
      if (typeof value === "string" && value.trim() && !out[target])
        out[target] = value.trim().slice(0, 1024);
    }
    return Object.keys(out).length ? out : undefined;
  }
  function itemToNativeMutation(item, options = {}) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const category = nativeCategory(item.category);
    if (!category || typeof item.title !== "string" || !item.title.trim()) return null;
    const out = { category, title: item.title.slice(0, 1024) };
    const password = typeof item.password === "string" ? item.password : "";
    const otp = typeof item.otp === "string" ? item.otp : typeof item.otp_secret === "string" ? item.otp_secret : "";
    const clearFields = validClearFields(item.clear_fields);
    if (!clearFields) return null;
    const clearSet = new Set(clearFields);
    let notes = typeof item.notes === "string" ? item.notes : typeof item.content === "string" ? item.content : undefined;
    if (clearSet.has("notes")) {
      if (typeof notes === "string" && notes !== "") return null;
      notes = "";
    } else if (notes === "" && options.original) {
      const originalNotes = Array.isArray(options.original.fields)
        ? options.original.fields.find((field) => field?.id === "notes")
        : null;
      const protectedMasked =
        (originalNotes &&
          (originalNotes.has_value === true || originalNotes.concealed === true) &&
          !originalNotes.value) ||
        (options.original.has_notes === true && !options.original.notes);
      if (protectedMasked && !options.original.notes) notes = undefined;
    }
    if (typeof item.username === "string" && item.username) out.username = item.username.slice(0, 16384);
    if (password) out.password = password.slice(0, 16384);
    if (otp.trim()) out.otp = otp.trim().slice(0, 4096);
    if (Array.isArray(item.urls)) out.urls = nativeURLs(item);
    if (notes !== undefined) out.notes = notes.slice(0, 65536);
    // Forward explicit clears so the host can audit and reject unknown or
    // non-concealed targets; an empty list stays omitted.
    if (clearFields.length) out.clear_fields = clearFields.slice(0, 100);
    if (typeof item.favorite === "boolean") out.favorite = item.favorite;
    if (typeof item.auto_submit === "boolean") out.auto_submit = item.auto_submit;
    if (Array.isArray(item.tags))
      out.tags = item.tags.filter((tag) => typeof tag === "string" && tag).slice(0, 50).map((tag) => tag.slice(0, 128));
    const sections = nativeSections(item, options.original, clearSet);
    if (sections) out.sections = sections;
    if (category === "credit_card") {
      const card = nativeCreditCard(item);
      if (card) out.credit_card = card;
    }
    if (category === "identity") {
      const identity = nativeIdentity(item);
      if (identity) out.identity = identity;
    }
    return out;
  }
  const ATTACHMENT_CAPABILITY = "attachments-v1";
  const PASSKEY_MANAGEMENT_CAPABILITY = "passkey-management-v1";
  // Native clipboard leasing. The capability is advertised by the native host
  // only when the desktop App actually owns a two-phase clipboard writer; the
  // popup must never treat a browser clipboard API as equivalent.
  const NATIVE_CLIPBOARD_CAPABILITY = "native-clipboard-lease-v1";
  const COPY_FIELD_PATTERN =
    /^(?:username|password|notes|url|otp|cc-number|cc-csc|cc-pin|section:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128})$/;
  const COPY_TICKET_PATTERN = /^[a-f0-9]{64}$/;
  function nativeClipboardCapability(capabilities) {
    return (
      Array.isArray(capabilities) &&
      capabilities.includes(NATIVE_CLIPBOARD_CAPABILITY)
    );
  }
  // Field selectors are bounded to the same fixed grammar the legacy copy path
  // accepts, so a native lease cannot be prepared for an invented field.
  function validCopyFieldSelector(field) {
    return typeof field === "string" && COPY_FIELD_PATTERN.test(field);
  }
  function validCopyTicket(ticket) {
    return typeof ticket === "string" && COPY_TICKET_PATTERN.test(ticket);
  }
  const CONDITIONAL_PASSKEY_CAPABILITY = "passkey-conditional-v1";
  const CONDITIONAL_PASSKEY_LIMIT = 50;
  const ATTACHMENT_MAX_BYTES = 2097152;
  const ATTACHMENT_CHUNK_BYTES = 65536;
  const ATTACHMENT_MAX_COUNT = 16;
  const ATTACHMENT_TRANSFER_TTL_SECONDS = 120;
  const B64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const CLEAR_FIELD_PATTERN =
    /^(?:notes|section:[A-Za-z0-9_.:-]{1,128}:[A-Za-z0-9_.:-]{1,128})$/;
  function attachmentCapability(capabilities) {
    return (
      Array.isArray(capabilities) &&
      capabilities.includes(ATTACHMENT_CAPABILITY)
    );
  }
  function passkeyManagementCapability(capabilities) {
    return (
      Array.isArray(capabilities) &&
      capabilities.includes(PASSKEY_MANAGEMENT_CAPABILITY)
    );
  }
  function conditionalPasskeyCapability(capabilities) {
    return (
      Array.isArray(capabilities) &&
      capabilities.includes(CONDITIONAL_PASSKEY_CAPABILITY)
    );
  }
  // WebAuthn Signal API hints (W3C WebAuthn Level 3). The page supplies public
  // RP metadata only; the native host re-validates the RP against the
  // browser-asserted origin, so these bounds never replace that check.
  const PASSKEY_SIGNAL_CAPABILITY = "passkey-signal-v1";
  const PASSKEY_SIGNAL_OPTIONS_MAX = 32768;
  const PASSKEY_SIGNAL_ACCEPTED_MAX = 64;
  const PASSKEY_SIGNAL_CREDENTIAL_MAX = 1024;
  const PASSKEY_SIGNAL_USER_ID_MAX = 64;
  const PASSKEY_SIGNAL_TEXT_MAX = 1024;
  const PASSKEY_SIGNAL_RPID_MAX = 253;
  const SIGNAL_B64URL = /^[A-Za-z0-9_-]+$/;
  const SIGNAL_RPID =
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
  function passkeySignalCapability(capabilities) {
    return (
      Array.isArray(capabilities) &&
      capabilities.includes(PASSKEY_SIGNAL_CAPABILITY)
    );
  }
  // Canonical un-padded base64url for a 1..max byte value. A non-canonical
  // spelling is refused so the native decoder sees exactly one encoding.
  function signalBase64URL(value, max) {
    if (typeof value !== "string" || value.length < 2) return false;
    if (value.length > max * 2 || !SIGNAL_B64URL.test(value)) return false;
    const bytes = base64URLDecode(value, max);
    return (
      !!bytes &&
      bytes.length >= 1 &&
      bytes.length <= max &&
      base64URLEncode(bytes) === value
    );
  }
  function signalText(value) {
    return (
      typeof value === "string" &&
      value.length <= PASSKEY_SIGNAL_TEXT_MAX &&
      (typeof value.isWellFormed !== "function" || value.isWellFormed()) &&
      !/[\x00\r\n]/.test(value)
    );
  }
  function signalRPID(value) {
    return (
      typeof value === "string" &&
      value.length >= 1 &&
      value.length <= PASSKEY_SIGNAL_RPID_MAX &&
      SIGNAL_RPID.test(value)
    );
  }
  // Strict re-walk of one signal options document: exact key set per kind,
  // bounded canonical selectors and text, no unknown keys. Returns the
  // normalised document the native parser accepts, or "" to ignore the hint.
  // The RP/origin policy itself always stays native.
  function passkeySignalOptions(raw) {
    if (
      typeof raw !== "string" ||
      raw.length < 2 ||
      raw.length > PASSKEY_SIGNAL_OPTIONS_MAX
    )
      return "";
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return "";
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return "";
    const keys = Object.keys(parsed);
    const exact = (names) =>
      keys.length === names.length && keys.every((key) => names.includes(key));
    let normalized;
    if (parsed.kind === "unknown") {
      if (!exact(["kind", "rpId", "credentialId"])) return "";
      if (!signalRPID(parsed.rpId)) return "";
      if (!signalBase64URL(parsed.credentialId, PASSKEY_SIGNAL_CREDENTIAL_MAX))
        return "";
      normalized = {
        kind: "unknown",
        rpId: parsed.rpId,
        credentialId: parsed.credentialId,
      };
    } else if (parsed.kind === "accepted") {
      if (!exact(["kind", "rpId", "userId", "allAcceptedCredentialIds"]))
        return "";
      if (!signalRPID(parsed.rpId)) return "";
      if (!signalBase64URL(parsed.userId, PASSKEY_SIGNAL_USER_ID_MAX)) return "";
      const list = parsed.allAcceptedCredentialIds;
      if (!Array.isArray(list) || list.length > PASSKEY_SIGNAL_ACCEPTED_MAX)
        return "";
      const ids = [];
      for (const id of list) {
        if (!signalBase64URL(id, PASSKEY_SIGNAL_CREDENTIAL_MAX)) return "";
        ids.push(id);
      }
      normalized = {
        kind: "accepted",
        rpId: parsed.rpId,
        userId: parsed.userId,
        allAcceptedCredentialIds: ids,
      };
    } else if (parsed.kind === "user") {
      if (!exact(["kind", "rpId", "userId", "name", "displayName"])) return "";
      if (!signalRPID(parsed.rpId)) return "";
      if (!signalBase64URL(parsed.userId, PASSKEY_SIGNAL_USER_ID_MAX)) return "";
      if (!signalText(parsed.name) || !signalText(parsed.displayName)) return "";
      normalized = {
        kind: "user",
        rpId: parsed.rpId,
        userId: parsed.userId,
        name: parsed.name,
        displayName: parsed.displayName,
      };
    } else return "";
    let out;
    try {
      out = JSON.stringify(normalized);
    } catch {
      return "";
    }
    return out.length <= PASSKEY_SIGNAL_OPTIONS_MAX ? out : "";
  }
  // The native acceptance frame is exactly {v,id,type}. Anything longer could
  // only be local credential metadata, so it is refused as a protocol error.
  function validPasskeySignalAck(value, requestId) {
    if (!value || typeof value !== "object" || Array.isArray(value))
      return false;
    const keys = Object.keys(value);
    if (keys.length !== 3) return false;
    if (!keys.every((key) => key === "v" || key === "id" || key === "type"))
      return false;
    if (value.v !== 1 || value.type !== "passkey-signal-accepted") return false;
    if (typeof value.id !== "string" || !/^[a-f0-9]{32}$/.test(value.id))
      return false;
    return requestId === undefined || value.id === requestId;
  }
  // Conditional (autofill) Passkey candidate list. Entries are public account
  // metadata only: no private key, user handle or raw credential bytes.
  function validConditionalPasskeyEntry(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const keys = [
      "item_id",
      "revision",
      "title",
      "credential_id",
      "rp_id",
      "user_name",
      "display_name",
    ];
    // credential_revision is the exact per-credential (child) selector a new
    // host supplies. A legacy candidate omits it entirely; no other public
    // key and no guessed revision is ever accepted.
    if (
      !Object.keys(value).every(
        (key) => keys.includes(key) || key === "credential_revision",
      )
    )
      return false;
    if (
      value.credential_revision !== undefined &&
      !validCredentialRevision(value.credential_revision)
    )
      return false;
    if (!/^[a-f0-9]{32}$/.test(value.item_id || "")) return false;
    if (!/^[a-f0-9]{64}$/.test(value.revision || "")) return false;
    if (!validCredentialID(value.credential_id)) return false;
    if (
      typeof value.rp_id !== "string" ||
      value.rp_id.length < 1 ||
      value.rp_id.length > 253 ||
      value.rp_id !== value.rp_id.toLowerCase() ||
      /[\x00-\x20\x7f]/.test(value.rp_id)
    )
      return false;
    for (const key of ["title", "user_name", "display_name"]) {
      const text = value[key];
      if (
        typeof text !== "string" ||
        text.length > 1024 ||
        !text.isWellFormed() ||
        /[\x00\r\n]/.test(text)
      )
        return false;
    }
    return true;
  }
  function validConditionalPasskeyList(value) {
    if (!Array.isArray(value) || value.length > CONDITIONAL_PASSKEY_LIMIT)
      return false;
    if (!value.every(validConditionalPasskeyEntry)) return false;
    const seen = new Set();
    for (const entry of value) {
      if (seen.has(entry.credential_id)) return false;
      seen.add(entry.credential_id);
    }
    return true;
  }
  function validAttachmentID(value) {
    return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
  }
  function safeFileName(raw) {
    if (typeof raw !== "string") return "";
    const value = raw.trim();
    if (!value || value.length > 255) return "";
    if (value === "." || value === "..") return "";
    if (/[\u0000-\u001f\u007f/\\]/.test(value)) return "";
    return value.isWellFormed() ? value : "";
  }
  function validMimeType(value) {
    return (
      typeof value === "string" &&
      value.length >= 1 &&
      value.length <= 255 &&
      /^[\x20-\x7e]+$/.test(value)
    );
  }
  function validAttachmentMetadata(meta) {
    if (!meta || typeof meta !== "object" || Array.isArray(meta)) return false;
    if (
      !Object.keys(meta).every((key) =>
        ["id", "file_name", "size", "mime_type", "sha256", "protected"].includes(
          key,
        ),
      )
    )
      return false;
    if (
      !validAttachmentID(meta.id) ||
      !safeFileName(meta.file_name) ||
      meta.file_name !== String(meta.file_name || "").trim() ||
      !Number.isSafeInteger(meta.size) ||
      meta.size < 0 ||
      meta.size > ATTACHMENT_MAX_BYTES ||
      typeof meta.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(meta.sha256)
    )
      return false;
    if (meta.mime_type !== undefined && !validMimeType(meta.mime_type))
      return false;
    if (meta.protected !== undefined && typeof meta.protected !== "boolean")
      return false;
    return true;
  }
  function validAttachmentList(list) {
    return (
      Array.isArray(list) &&
      list.length <= ATTACHMENT_MAX_COUNT &&
      list.every(validAttachmentMetadata)
    );
  }
  function base64Encode(bytes) {
    if (!bytes || typeof bytes.length !== "number") return "";
    const length = bytes.length;
    if (!Number.isSafeInteger(length) || length < 0) return "";
    if (length > ATTACHMENT_MAX_BYTES) return "";
    let out = "";
    for (let i = 0; i < length; i += 3) {
      const a = bytes[i] & 0xff;
      const b = i + 1 < length ? bytes[i + 1] & 0xff : 0;
      const c = i + 2 < length ? bytes[i + 2] & 0xff : 0;
      out += B64_ALPHABET[a >> 2];
      out += B64_ALPHABET[((a & 3) << 4) | (b >> 4)];
      out += i + 1 < length ? B64_ALPHABET[((b & 15) << 2) | (c >> 6)] : "=";
      out += i + 2 < length ? B64_ALPHABET[c & 63] : "=";
    }
    return out;
  }
  function base64Decode(text, maxBytes = ATTACHMENT_CHUNK_BYTES) {
    if (typeof text !== "string") return null;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) return null;
    if (maxBytes > ATTACHMENT_MAX_BYTES) return null;
    const length = text.length;
    if (length % 4 !== 0) return null;
    if (length > Math.ceil(maxBytes / 3) * 4) return null;
    if (length === 0) return new Uint8Array(0);
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        text,
      )
    )
      return null;
    if (text.indexOf("=") !== -1 && text.indexOf("=") < length - 2) return null;
    const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
    const size = (length / 4) * 3 - padding;
    if (size > maxBytes) return null;
    const bytes = new Uint8Array(size);
    let index = 0;
    for (let i = 0; i < length; i += 4) {
      const a = B64_ALPHABET.indexOf(text[i]);
      const b = B64_ALPHABET.indexOf(text[i + 1]);
      const c = text[i + 2] === "=" ? 0 : B64_ALPHABET.indexOf(text[i + 2]);
      const d = text[i + 3] === "=" ? 0 : B64_ALPHABET.indexOf(text[i + 3]);
      if (a < 0 || b < 0 || c < 0 || d < 0) return null;
      const triple = (a << 18) | (b << 12) | (c << 6) | d;
      if (index < size) bytes[index++] = (triple >> 16) & 0xff;
      if (index < size) bytes[index++] = (triple >> 8) & 0xff;
      if (index < size) bytes[index++] = triple & 0xff;
    }
    return index === size ? bytes : null;
  }
  function base64URLEncode(bytes) {
    return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function base64URLDecode(text, maxBytes = ATTACHMENT_CHUNK_BYTES) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
    const padded =
      text.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (text.length % 4)) % 4);
    return base64Decode(padded, maxBytes);
  }
  function validCredentialID(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 1024)
      return false;
    const bytes = base64URLDecode(value, 1024);
    return !!bytes && bytes.length === 32 && base64URLEncode(bytes) === value;
  }
  // Opaque per-credential content revision: canonical lowercase 64 hex, the
  // exact child selector that must travel with its credential ID.
  function validCredentialRevision(value) {
    return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  }
  // Detail-frame bound for per-credential metadata. A list row carries only
  // passkey_count so a 256-row list can never approach the output budget.
  const PASSKEY_METADATA_LIMIT = 16;
  function validPasskeyMetadataList(value) {
    if (!Array.isArray(value) || value.length > PASSKEY_METADATA_LIMIT)
      return false;
    const seen = new Set();
    for (const entry of value) {
      if (!validPasskeyMetadata(entry)) return false;
      if (!validCredentialRevision(entry.credential_revision)) return false;
      if (seen.has(entry.credential_id)) return false;
      seen.add(entry.credential_id);
    }
    return true;
  }
  function validPasskeyMetadata(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    if (
      !Object.keys(value).every((key) =>
        [
          "credential_id",
          "rp_id",
          "user_name",
          "display_name",
          "credential_revision",
        ].includes(key),
      ) ||
      (value.credential_revision !== undefined &&
        !validCredentialRevision(value.credential_revision))
    )
      return false;
    if (!validCredentialID(value.credential_id)) return false;
    if (
      typeof value.rp_id !== "string" ||
      value.rp_id.length < 1 ||
      value.rp_id.length > 253 ||
      value.rp_id !== value.rp_id.toLowerCase() ||
      /[\x00-\x20\x7f]/.test(value.rp_id)
    )
      return false;
    for (const key of ["user_name", "display_name"]) {
      const text = value[key];
      if (
        typeof text !== "string" ||
        text.length > 1024 ||
        !text.isWellFormed() ||
        /[\x00\r\n]/.test(text)
      )
        return false;
    }
    return true;
  }
  function attachmentStableKey(sectionID, fieldID) {
    if (
      typeof sectionID !== "string" ||
      !/^[A-Za-z0-9_.:-]{1,128}$/.test(sectionID) ||
      typeof fieldID !== "string" ||
      !/^[A-Za-z0-9_.:-]{1,128}$/.test(fieldID)
    )
      return "";
    return "section:" + sectionID + ":" + fieldID;
  }
  function validClearFields(value) {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.length > 100) return null;
    const result = [];
    for (const key of value) {
      if (typeof key !== "string" || !CLEAR_FIELD_PATTERN.test(key)) return null;
      if (result.includes(key)) return null;
      result.push(key);
    }
    return result;
  }
  // Strict metadata-only profile rows for the native `match-profiles` reply
  // (internal/browserhost/vault_ops.go handleMatchProfiles ->
  // types_v2.go BrowserProfileSummary). Every field the host marshals is
  // listed here exactly; display hints are the only optional members.
  // Card number, CVV/PIN, SSN, raw user ids and full records never fit this
  // shape, so an unknown or oversized member is refused outright.
  const MAX_PROFILE_METADATA = 100;
  const PROFILE_METADATA_KEYS = Object.freeze([
    "id",
    "revision",
    "category",
    "title",
    "subtitle",
    "card_brand",
    "card_last4",
    "card_exp",
  ]);
  const CARD_ONLY_PROFILE_KEYS = Object.freeze([
    "card_brand",
    "card_last4",
    "card_exp",
  ]);
  function validProfileText(value, maxLength) {
    return (
      typeof value === "string" &&
      value.length <= maxLength &&
      value.isWellFormed()
    );
  }
  function validProfileMeta(value) {
    if (!plainObject(value)) return false;
    if (!knownKeysOnly(value, PROFILE_METADATA_KEYS)) return false;
    if (typeof value.id !== "string" || !/^[a-f0-9]{32}$/.test(value.id))
      return false;
    if (
      typeof value.revision !== "string" ||
      !/^[a-f0-9]{64}$/.test(value.revision)
    )
      return false;
    if (value.category !== "credit_card" && value.category !== "identity")
      return false;
    if (
      !validProfileText(value.title, 1024) ||
      (value.subtitle !== undefined && !validProfileText(value.subtitle, 1024))
    )
      return false;
    if (
      value.card_brand !== undefined &&
      !validProfileText(value.card_brand, 64)
    )
      return false;
    if (value.card_exp !== undefined && !validProfileText(value.card_exp, 32))
      return false;
    if (
      value.card_last4 !== undefined &&
      !(
        typeof value.card_last4 === "string" &&
        /^[0-9]{1,4}$/.test(value.card_last4)
      )
    )
      return false;
    if (
      value.category === "identity" &&
      CARD_ONLY_PROFILE_KEYS.some((key) => value[key] !== undefined)
    )
      return false;
    return true;
  }
  function validProfileList(value) {
    if (!Array.isArray(value) || value.length > MAX_PROFILE_METADATA)
      return false;
    const seen = new Set();
    for (const row of value) {
      if (!validProfileMeta(row)) return false;
      // A duplicate metadata id would make the picker selection ambiguous.
      if (seen.has(row.id)) return false;
      seen.add(row.id);
    }
    return true;
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
        "passkey-candidates": ["v", "id", "type", "passkeys", "truncated"],
        // WebAuthn signal ACK: the exact fixed frame, never metadata.
        "passkey-signal-accepted": ["v", "id", "type"],
        locked: ["v", "type"],
        unpaired: ["v", "type", "error"],
        paired: ["v", "id", "type", "capability", "quick_fill", "capabilities"],
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
        "vault-items": ["v", "id", "type", "items"],
        // Native host v2 vault protocol (internal/browserhost/vault_ops.go).
        items: ["v", "id", "type", "items", "vaults"],
        // match-profiles reply: exact {v, id, type, profiles} frame.
        profiles: ["v", "id", "type", "profiles"],
        "item-saved": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "item_summary",
          "state",
          "favorite",
        ],
        "profile-fill": ["v", "id", "type", "profile_fill"],
        "item-detail": ["v", "id", "type", "item"],
        "copy-prepared": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "field",
          "copy_ticket",
          "copy_mode",
          "cleanup_ttl_seconds",
          "expires_in_seconds",
        ],
        "copy-result": [
          "v",
          "id",
          "type",
          "copy_ticket",
          "copy_mode",
          "copied",
          "state",
        ],
        "copy-cancelled": [
          "v",
          "id",
          "type",
          "copy_ticket",
          "copy_mode",
          "state",
        ],
        "field-value": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "field",
          "value",
          "copied",
          "expires_in_seconds",
        ],
        "fill-fields": ["v", "id", "type", "fields"],
        "attachment-transfer": [
          "v",
          "id",
          "type",
          "transfer_id",
          "offset",
          "size",
          "expires_in_seconds",
        ],
        "attachment-saved": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "attachment",
        ],
        "attachment-cancelled": ["v", "id", "type", "transfer_id"],
        "attachment-data": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "attachment",
          "offset",
          "next_offset",
          "done",
          "data",
        ],
        "attachment-removed": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "attachment_id",
        ],
        "passkey-removed": [
          "v",
          "id",
          "type",
          "item_id",
          "revision",
          "credential_id",
        ],
        watchtower: ["v", "id", "type", "watchtower"],
        unknown: ["v", "id", "type"],
        generated: [
          "v",
          "id",
          "type",
          "generated_password",
          "profile",
          "history_id",
          "password",
        ],
        "save-staged": ["v", "id", "type", "staged_save"],
        "save-pending": ["v", "id", "type", "staged_save"],
        "save-dismissed": ["v", "id", "type", "never_origins"],
        unlocked: [
          "v",
          "type",
          "capability",
          "quick_fill",
          "desktop_connected",
          "unlocked",
          "session_epoch",
          "capabilities",
        ],
      },
      keys = shapes[m.type];
    if (!keys || !hasOnly(m, keys)) return false;
    if (m.type === "locked") return true;
    if (m.type === "unpaired") return m.error === "expired";
    if (m.type === "unlocked")
      return (
        m.v === 1 &&
        /^[a-f0-9]{32}$/.test(m.capability || "") &&
        (m.quick_fill === undefined || typeof m.quick_fill === "boolean") &&
        (m.desktop_connected === undefined ||
          m.desktop_connected === true) &&
        (m.unlocked === undefined || m.unlocked === true) &&
        (m.session_epoch === undefined ||
          (Number.isSafeInteger(m.session_epoch) && m.session_epoch >= 0)) &&
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
    if (!/^[a-f0-9]{32}$/.test(m.id || "")) return false;
    if (!validCategory(m.category)) return false;
    if (m.type === "attachment-transfer")
      return (
        /^[a-f0-9]{32}$/.test(m.transfer_id || "") &&
        boundedInteger(m.offset, 0, ATTACHMENT_MAX_BYTES) &&
        boundedInteger(m.size, 0, ATTACHMENT_MAX_BYTES) &&
        boundedInteger(m.expires_in_seconds, 1, 3600) &&
        m.offset <= m.size
      );
    if (m.type === "attachment-saved")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        validAttachmentMetadata(m.attachment)
      );
    if (m.type === "attachment-cancelled")
      return /^[a-f0-9]{32}$/.test(m.transfer_id || "");
    if (m.type === "copy-prepared")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        validCopyFieldSelector(m.field) &&
        validCopyTicket(m.copy_ticket) &&
        m.copy_mode === "native" &&
        (m.cleanup_ttl_seconds === undefined ||
          boundedInteger(m.cleanup_ttl_seconds, 0, 3600)) &&
        (m.expires_in_seconds === undefined ||
          boundedInteger(m.expires_in_seconds, 0, 15))
      );
    if (m.type === "copy-result")
      return (
        validCopyTicket(m.copy_ticket) &&
        m.copy_mode === "native" &&
        ["confirmed", "refused", "unknown"].includes(m.state) &&
        // A denied or unknown commit may omit the false flag entirely; a
        // confirmed result must state it explicitly.
        (m.state === "confirmed"
          ? m.copied === true
          : m.copied === undefined || m.copied === false)
      );
    if (m.type === "copy-cancelled")
      return (
        validCopyTicket(m.copy_ticket) &&
        m.copy_mode === "native" &&
        (m.state === undefined || m.state === "pending")
      );
    if (m.type === "attachment-removed")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        validAttachmentID(m.attachment_id)
      );
    if (m.type === "passkey-removed")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        validCredentialID(m.credential_id)
      );
    if (m.type === "attachment-data") {
      if (
        !/^[a-f0-9]{32}$/.test(m.item_id || "") ||
        !/^[a-f0-9]{64}$/.test(m.revision || "") ||
        !validAttachmentMetadata(m.attachment) ||
        !boundedInteger(m.offset, 0, ATTACHMENT_MAX_BYTES) ||
        !boundedInteger(m.next_offset, 0, ATTACHMENT_MAX_BYTES) ||
        typeof m.done !== "boolean"
      )
        return false;
      const bytes = base64Decode(m.data, ATTACHMENT_CHUNK_BYTES);
      if (!bytes) return false;
      if (m.offset > m.attachment.size) return false;
      if (m.next_offset !== m.offset + bytes.length) return false;
      if (m.next_offset > m.attachment.size) return false;
      return m.done === (m.next_offset === m.attachment.size);
    }
    if (m.type === "watchtower") return validWatchtower(m.watchtower);
    if (m.type === "passkey-result")
      return typeof m.credential === "string" && m.credential.length <= 32768;
    if (m.type === "passkey-candidates")
      return (
        typeof m.truncated === "boolean" &&
        validConditionalPasskeyList(m.passkeys)
      );
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
    if (m.type === "vault-items" || m.type === "items")
      return (
        Array.isArray(m.items) &&
        m.items.length <= 500 &&
        (m.vaults === undefined ||
          (Array.isArray(m.vaults) &&
            m.vaults.length <= 256 &&
            m.vaults.every(
              (vault) =>
                vault && typeof vault === "object" && !Array.isArray(vault),
            ))) &&
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
    if (m.type === "profiles") return validProfileList(m.profiles);
    if (m.type === "item-saved")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        (m.state === undefined ||
          ["active", "archived", "trashed"].includes(m.state)) &&
        (m.favorite === undefined || typeof m.favorite === "boolean") &&
        (m.item_summary === undefined ||
          (!!m.item_summary &&
            typeof m.item_summary === "object" &&
            !Array.isArray(m.item_summary)))
      );
    if (m.type === "field-value")
      return (
        /^[a-f0-9]{32}$/.test(m.item_id || "") &&
        /^[a-f0-9]{64}$/.test(m.revision || "") &&
        typeof m.field === "string" &&
        /^(?:username|password|notes|url|otp|cc-number|cc-csc|cc-pin|section:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128})$/.test(m.field) &&
        typeof m.value === "string" &&
        m.value.length <= 16384 &&
        typeof m.copied === "boolean" &&
        Number.isSafeInteger(m.expires_in_seconds) &&
        m.expires_in_seconds >= 0 &&
        m.expires_in_seconds <= 3600
      );
    if (m.type === "profile-fill") {
      const fill = m.profile_fill;
      return (
        !!fill &&
        typeof fill === "object" &&
        !Array.isArray(fill) &&
        /^[a-f0-9]{32}$/.test(fill.item_id || "") &&
        /^[a-f0-9]{64}$/.test(fill.revision || "") &&
        typeof fill.category === "string" &&
        fill.category.length <= 64 &&
        !!fill.fields &&
        typeof fill.fields === "object" &&
        !Array.isArray(fill.fields) &&
        Object.keys(fill.fields).length <= 100 &&
        Object.entries(fill.fields).every(
          ([key, value]) =>
            /^[A-Za-z0-9_.-]{1,128}$/.test(key) &&
            typeof value === "string" &&
            value.length <= 16384,
        )
      );
    }
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
        m.item.category.length <= 64 &&
        (m.item.attachments === undefined ||
          validAttachmentList(m.item.attachments))
      );
    if (m.type === "generated") {
      if (typeof m.password === "string")
        return m.password.length > 0 && m.password.length <= 1024;
      return (
        typeof m.generated_password === "string" &&
        m.generated_password.length >= 4 &&
        m.generated_password.length <= 256 &&
        m.generated_password.isWellFormed() &&
        validGeneratedProfile(m.profile) &&
        (m.history_id === undefined || /^[a-f0-9]{32}$/.test(m.history_id))
      );
    }
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

    if (m.type === "save-staged")
      return validStagedSave(m.staged_save);
    if (m.type === "save-pending")
      return m.staged_save === undefined || validStagedSave(m.staged_save);
    if (m.type === "save-dismissed")
      return m.never_origins === undefined || validOriginList(m.never_origins);
    if (m.type === "error") return m.error === "refused";
    if (m.type === "candidates")
      return (
        m.candidates === undefined ||
        (Array.isArray(m.candidates) &&
          m.candidates.length <= 100 &&
          m.candidates.every(validCandidate))
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
  function generatePasswordObject(options = {}) {
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
  // Self-contained checkout probe for api.scripting.executeScript({ func }).
  // No closure helper is referenced: the browser serializes this function into
  // the target isolated world. It reports only public booleans plus the
  // browser-observed origin; the native host keeps frame/document identity and
  // the registrable-domain check as the authority. A missing fence is never
  // initialized here, it is simply reported as unsupported.
  function checkoutProbe() {
    "use strict";
    let origin = "",
      protocol = "",
      href = "",
      windowOrigin = "",
      secure = false;
    try {
      origin = String(location.origin || "");
    } catch {}
    try {
      protocol = String(location.protocol || "");
    } catch {}
    try {
      href = String(location.href || "");
    } catch {}
    try {
      windowOrigin = String(window.origin || "");
    } catch {}
    try {
      secure = isSecureContext === true;
    } catch {
      secure = false;
    }
    if (
      origin === "" ||
      origin === "null" ||
      origin.indexOf("https://") !== 0 ||
      (protocol !== "" && protocol !== "https:") ||
      (href !== "" && href.indexOf("https://") !== 0) ||
      windowOrigin === "null"
    ) {
      origin = "";
      secure = false;
    }
    let top = false;
    try {
      top = window === window.top;
    } catch {
      top = false;
    }
    let fencePresent = false,
      documentStable = false,
      sandboxEver = true;
    try {
      const fence = globalThis.LocklarkCheckoutFence;
      if (typeof fence === "function") {
        const snap = fence();
        if (snap && typeof snap === "object") {
          fencePresent = true;
          documentStable = snap.document_stable === true;
          sandboxEver = snap.sandbox_ever === true;
        }
      }
    } catch {
      fencePresent = false;
      documentStable = false;
      sandboxEver = true;
    }
    return {
      origin,
      top,
      secure,
      fence_present: fencePresent,
      document_stable: documentStable,
      sandbox_ever: sandboxEver,
    };
  }
  // Self-contained exact-document card injection for executeScript({ func }).
  // The native host already approved this exact frame document; this helper only
  // re-validates the current isolated document, requires every candidate to be
  // unique before the first write, and never submits, navigates, reads the
  // clipboard or bridges to the page. It returns counts, never values. If the
  // DOM changes after a partial write it reports `unknown` instead of retrying
  // or claiming a rollback.
  function fillCheckoutCardDocument(
    expectedOrigin,
    fields,
    deadlineMs,
    allowTop,
  ) {
    "use strict";
    const MAX_FIELD_BYTES = 16384;
    const MAX_TOTAL_BYTES = 32768;
    const ALLOWED = {
      "cc-name": true,
      "cc-number": true,
      "cc-exp": true,
      "cc-exp-month": true,
      "cc-exp-year": true,
      "cc-exp-year-short": true,
      "cc-csc": true,
      "cc-type": true,
    };
    const refuse = () => ({ filled: false, count: 0 });
    const nowMs = () => Date.now();
    function utf8Length(value) {
      try {
        if (typeof TextEncoder === "function")
          return new TextEncoder().encode(value).length;
      } catch {}
      return value.length;
    }
    function autocompleteTokens(el) {
      let raw = "";
      try {
        raw =
          el && typeof el.getAttribute === "function"
            ? el.getAttribute("autocomplete")
            : "";
      } catch {
        raw = "";
      }
      if ((raw === null || raw === undefined || raw === "") && el) {
        try {
          raw = typeof el.autocomplete === "string" ? el.autocomplete : "";
        } catch {
          raw = "";
        }
      }
      return String(raw || "")
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
    }
    function visible(el) {
      if (!el || typeof el !== "object") return false;
      try {
        if (el.isConnected === false) return false;
        if (el.disabled === true || el.readOnly === true) return false;
        if (typeof el.matches === "function" && el.matches(":disabled"))
          return false;
        const tag = String(el.tagName || "").toUpperCase();
        if (tag !== "INPUT" && tag !== "SELECT") return false;
        if (
          tag === "INPUT" &&
          String(el.type || "").toLowerCase() === "hidden"
        )
          return false;
        if (
          typeof el.closest === "function" &&
          el.closest("[hidden],[inert],[aria-hidden='true']")
        )
          return false;
        for (let n = el; n && typeof n === "object"; n = n.parentElement) {
          const style = getComputedStyle(n);
          if (
            !style ||
            style.display === "none" ||
            style.visibility === "hidden" ||
            style.visibility === "collapse" ||
            Number(style.opacity) === 0
          )
            return false;
          if (!n.parentElement) break;
        }
        const rect =
          typeof el.getBoundingClientRect === "function"
            ? el.getBoundingClientRect()
            : null;
        return !!rect && rect.width > 0 && rect.height > 0;
      } catch {
        return false;
      }
    }
    function valueSetter(el) {
      try {
        const tag = String(el.tagName || "").toUpperCase();
        const proto =
          tag === "SELECT"
            ? typeof HTMLSelectElement !== "undefined"
              ? HTMLSelectElement.prototype
              : null
            : typeof HTMLInputElement !== "undefined"
              ? HTMLInputElement.prototype
              : null;
        if (!proto) return null;
        const desc = Object.getOwnPropertyDescriptor(proto, "value");
        return desc && typeof desc.set === "function" ? desc.set : null;
      } catch {
        return null;
      }
    }
    function selectValue(el, value) {
      let options = null;
      try {
        options = el.options || null;
      } catch {
        options = null;
      }
      if (!options) return null;
      const target = String(value).trim();
      if (target === "") return null;
      const lower = target.toLowerCase();
      const usable = [];
      for (let i = 0; i < options.length; i++) {
        const option = options[i];
        if (!option || option.disabled) continue;
        const optionValue = String(option.value == null ? "" : option.value);
        if (optionValue === "") continue;
        let text = "";
        try {
          text =
            option.text != null
              ? String(option.text)
              : option.textContent != null
                ? String(option.textContent)
                : "";
        } catch {
          text = "";
        }
        usable.push({ value: optionValue, text });
      }
      for (const option of usable)
        if (option.value === target || option.value.toLowerCase() === lower)
          return option.value;
      for (const option of usable)
        if (option.text.trim().toLowerCase() === lower) return option.value;
      const numeric = Number(target);
      if (Number.isFinite(numeric))
        for (const option of usable) {
          const optionNumber = Number(option.value.trim());
          if (Number.isFinite(optionNumber) && optionNumber === numeric)
            return option.value;
        }
      return null;
    }
    // --- environment validation ------------------------------------------------
    let origin = "",
      protocol = "",
      href = "",
      windowOrigin = "";
    try {
      origin = String(location.origin || "");
      protocol = String(location.protocol || "");
      href = String(location.href || "");
    } catch {
      return refuse();
    }
    try {
      windowOrigin = String(window.origin || "");
    } catch {
      windowOrigin = "";
    }
    if (
      typeof expectedOrigin !== "string" ||
      origin === "" ||
      origin === "null" ||
      origin !== expectedOrigin ||
      origin.indexOf("https://") !== 0
    )
      return refuse();
    if (protocol !== "" && protocol !== "https:") return refuse();
    if (href !== "" && href.indexOf("https://") !== 0) return refuse();
    if (windowOrigin === "null") return refuse();
    try {
      if (isSecureContext !== true) return refuse();
    } catch {
      return refuse();
    }
    const started = nowMs();
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= started)
      return refuse();
    if (deadlineMs - started > 1500) return refuse();
    let isTop = false;
    try {
      isTop = window === window.top;
    } catch {
      isTop = false;
    }
    if (isTop !== (allowTop === true)) return refuse();
    let fence = null;
    try {
      fence = globalThis.LocklarkCheckoutFence;
    } catch {
      fence = null;
    }
    if (typeof fence !== "function") return refuse();
    let snap = null;
    try {
      snap = fence();
    } catch {
      return refuse();
    }
    if (!snap || snap.document_stable !== true || snap.sandbox_ever !== false)
      return refuse();
    // --- private field whitelist and bounds -----------------------------------
    if (!fields || typeof fields !== "object" || Array.isArray(fields))
      return refuse();
    const entries = [];
    let totalBytes = 0;
    for (const key of Object.keys(fields)) {
      if (!Object.prototype.hasOwnProperty.call(ALLOWED, key)) return refuse();
      const value = fields[key];
      if (
        typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_FIELD_BYTES
      )
        return refuse();
      const bytes = utf8Length(value);
      if (bytes > MAX_FIELD_BYTES) return refuse();
      totalBytes += bytes;
      if (totalBytes > MAX_TOTAL_BYTES) return refuse();
      entries.push([key, value]);
    }
    if (entries.length === 0 || entries.length > 8) return refuse();
    // --- preflight every candidate before the first write ---------------------
    let pool = null;
    let byKey = null;
    const usedNodes = new Set();
    const plan = [];
    try {
      try {
        pool = document.querySelectorAll("input,select");
      } catch {
        return refuse();
      }
      byKey = new Map();
      for (const el of pool || []) {
        if (!visible(el)) continue;
        const tokens = autocompleteTokens(el);
        for (const [key] of entries) {
          if (tokens.indexOf(key) === -1) continue;
          const list = byKey.get(key) || [];
          list.push(el);
          byKey.set(key, list);
        }
      }
      for (const [key, value] of entries) {
        const list = byKey.get(key) || [];
        if (list.length === 0) continue;
        if (list.length > 1) return refuse(); // ambiguous autocomplete token
        const node = list[0];
        if (usedNodes.has(node)) return refuse(); // one node for two fields
        let resolved = value;
        if (String(node.tagName || "").toUpperCase() === "SELECT") {
          // A visible intended select whose requested option is absent must
          // refuse the entire fill before any write: never leave the select
          // stale while other valid fields were already filled.
          resolved = selectValue(node, value);
          if (resolved === null) return refuse();
        }
        const setter = valueSetter(node);
        if (typeof setter !== "function") continue;
        usedNodes.add(node);
        plan.push({ key, node, setter, resolved });
      }
      if (plan.length === 0) return refuse();
      let root = null;
      try {
        root = document.documentElement || null;
      } catch {
        root = null;
      }
      const unchanged = (entry) => {
        try {
          if (nowMs() >= deadlineMs) return false;
          if (String(location.origin || "") !== expectedOrigin) return false;
          if ((document.documentElement || null) !== root) return false;
          const node = entry.node;
          if (!node || node.isConnected === false) return false;
          if (!visible(node)) return false;
          return autocompleteTokens(node).indexOf(entry.key) !== -1;
        } catch {
          return false;
        }
      };
      let written = 0;
      for (const entry of plan) {
        if (!unchanged(entry)) {
          return written > 0
            ? { filled: false, count: written, unknown: true }
            : refuse();
        }
        entry.setter.call(entry.node, entry.resolved);
        try {
          entry.node.dispatchEvent(new Event("input", { bubbles: true }));
          entry.node.dispatchEvent(new Event("change", { bubbles: true }));
        } catch {}
        written++;
      }
      return { filled: written > 0, count: written };
    } finally {
      // Best-effort reference drop only; string contents are not claimed zeroable.
      if (byKey) byKey.clear();
      usedNodes.clear();
      plan.length = 0;
      pool = null;
    }
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
          el.matches("[data-1p-ignore],[data-locklark-ignore]") ||
          el.closest(
            '[hidden],[inert],[aria-hidden="true"],[data-1p-ignore],[data-locklark-ignore]',
          )
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
      const allInputs = deepAll(document, "input");
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
          (!pass || logicalForm(e) === logicalForm(pass)),
      );
      const semantic = users.filter(
        (e) =>
          hasAutocomplete(e, "username") ||
          e.type === "email" ||
          /^(user(name)?|login|email)$/i.test(e.name || e.id),
      );
      // Capture persists page values, so an extra visible text field keeps it
      // ambiguous; only fill narrows to the single semantic username field.
      if (semantic.length === 1 && !captureOnly) users = semantic;
      if (users.length > 1) return false;
      const user = users[0] || null,
        form = logicalForm(pass || user);
      if (!form) return false;
      if (form.ownerDocument && form.ownerDocument !== document) return false;
      if (
        captureOnly &&
        ((pass && user && pass.form !== form) ||
          passwords.some((e) => e.form !== form))
      )
        return false;
      if (pass && user && logicalForm(pass) !== logicalForm(user)) return false;
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
          (e) =>
            ["text", "email"].includes(e.type) &&
            logicalForm(e) === logicalForm(pass),
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
      function actionOf(target) {
        return target && typeof target.getAttribute === "function"
          ? target.getAttribute("action")
          : null;
      }
      if (!sameAction(actionOf(form))) return false;
      for (const el of deepAll(document, "button[formaction],input[formaction]"))
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
        (user && (!eligible(user) || logicalForm(user) !== form)) ||
        (pass && (!eligible(pass) || logicalForm(pass) !== form)) ||
        (captureOnly &&
          [currentPass, newPass, confirmPass]
            .filter(Boolean)
            .some((el) => !eligible(el) || el.form !== form)) ||
        !sameAction(actionOf(form)) ||
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
        // Chrome's scripting JSON transport turns `undefined` array entries into
        // `null`, so both spellings are the no-payload sentinel for a probe.
        // Any real code/timing in probe mode is still refused outright.
        const empty = (value) => value === undefined || value === null;
        if (!empty(code) || !empty(timing)) return false;
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
        // A formless single field has no verifiable submit target; refuse it.
        // Split-box widgets are often formless and are gated by groupValid().
        if (!target.form && target.kind !== "split") return false;
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
    pasteProtection: true,
    otpCapture: true,
    idleLockMinutes: 0,
    notifications: false,
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
    watchtowerHIBP: false,
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
  function validFilterCategory(raw) {
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
      "pasteProtection",
      "otpCapture",
      "notifications",
      "watchtowerLocalChecks",
      "watchtowerHIBP",
    ])
      if (typeof source[key] === "boolean") result[key] = source[key];
    result.clipboardClearSeconds = Number.isSafeInteger(
      source.clipboardClearSeconds,
    )
      ? Math.max(5, Math.min(300, source.clipboardClearSeconds))
      : DEFAULT_SETTINGS.clipboardClearSeconds;
    result.idleLockMinutes = [0, 1, 5, 15, 30, 60].includes(
      source.idleLockMinutes,
    )
      ? source.idleLockMinutes
      : DEFAULT_SETTINGS.idleLockMinutes;
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
  function sameVaultSite(a, b) {
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
      else if (siteWide && sameVaultSite(candidate, origin)) return true;
    }
    return exact;
  }
  function flattenItemFields(item) {
    if (!item || typeof item !== "object") return [];
    const result = [];
    const seen = new Set();
    const bounded = (value, length) =>
      typeof value === "string" ? value.slice(0, length) : "";
    const sectionFields = new Map();
    if (Array.isArray(item.sections))
      for (const section of item.sections.slice(0, 20))
        if (
          typeof section?.id === "string" &&
          section.id &&
          Array.isArray(section?.fields)
        )
          for (const field of section.fields.slice(0, 100))
            if (typeof field?.id === "string" && field.id)
              sectionFields.set(field.id, section);
    const add = (field, section = null) => {
      if (!field || typeof field !== "object" || Array.isArray(field)) return;
      if (result.length >= 200) return;
      const rawID = bounded(field.id, 128);
      const sectionID = section
        ? bounded(section.id, 128)
        : bounded(field.section_id, 128);
      const id =
        section && sectionID && rawID
          ? "section:" + sectionID + ":" + rawID
          : rawID;
      // A native section field is exposed only by its qualified stable key.
      if (!section && rawID && sectionFields.has(rawID)) return;
      const stableKey = id || bounded(field.label, 256) + ":" + nativeFieldType(field.type);
      if (seen.has(stableKey)) return;
      seen.add(stableKey);
      const out = {
        id,
        label: bounded(field.label, 256),
        type: FIELD_TYPES.includes(field.type) ? field.type : nativeFieldType(field.type),
        value: bounded(field.value, 16384),
        concealed: field.concealed === true,
      };
      if (typeof field.has_value === "boolean") out.has_value = field.has_value;
      if (typeof field.revealable === "boolean") out.revealable = field.revealable;
      const outSectionID = section ? sectionID : bounded(field.section_id, 128);
      const outSectionTitle = section
        ? bounded(section.title, 256)
        : bounded(field.section_title, 256);
      if (outSectionID) out.section_id = outSectionID;
      if (outSectionTitle) out.section_title = outSectionTitle;
      if (typeof field.purpose === "string" && field.purpose)
        out.purpose = bounded(field.purpose, 128);
      result.push(out);
    };
    if (Array.isArray(item.fields)) item.fields.slice(0, 100).forEach((field) => add(field));
    if (Array.isArray(item.sections))
      for (const section of item.sections.slice(0, 20))
        if (Array.isArray(section?.fields))
          section.fields.slice(0, 100).forEach((field) => add(field, section));
    if (Array.isArray(item.custom_fields))
      item.custom_fields.slice(0, 100).forEach((field) => add(field));
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
    const category = validFilterCategory(options.category) ? options.category : "all";
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
    if (item.clear_fields !== undefined && !validClearFields(item.clear_fields))
      return false;
    if (item.sections !== undefined) {
      if (!Array.isArray(item.sections) || item.sections.length > 20) return false;
    }
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
  function secureRandom() {
    const source = globalThis.crypto;
    if (!source || typeof source.getRandomValues !== "function")
      throw Error("refused");
    const values = new Uint32Array(1);
    source.getRandomValues(values);
    return values[0] / 4294967296;
  }
  function generatePasswordString(options = {}, random = secureRandom) {
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
  function generatePassword(options = {}, random) {
    if (typeof random === "function")
      return generatePasswordString(options, random);
    return generatePasswordObject(options);
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
    generatePassword,
    classifyPasswordFields,
    validCandidate,
    validWatchtower,
    watchtowerFlagsForRow,
    validWebOrigin,
    validHTTPSOrigin,
    siteFromURL,
    probe,
    fillDocument,
    fillGeneratedPassword,
    checkoutProbe,
    fillCheckoutCardDocument,
    fillGeneratedPasswordDocument,
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
    nativeCategory,
    nativeFieldType,
    stableFieldID,
    nativeURLs,
    nativeSections,
    nativeCreditCard,
    nativeIdentity,
    itemToNativeMutation,
    itemURLAllowed,
    ATTACHMENT_CAPABILITY,
    ATTACHMENT_MAX_BYTES,
    ATTACHMENT_CHUNK_BYTES,
    ATTACHMENT_MAX_COUNT,
    ATTACHMENT_TRANSFER_TTL_SECONDS,
    attachmentCapability,
    PASSKEY_MANAGEMENT_CAPABILITY,
    NATIVE_CLIPBOARD_CAPABILITY,
    nativeClipboardCapability,
    validCopyFieldSelector,
    validCopyTicket,
    passkeyManagementCapability,
    CONDITIONAL_PASSKEY_CAPABILITY,
    CONDITIONAL_PASSKEY_LIMIT,
    conditionalPasskeyCapability,
    PASSKEY_SIGNAL_CAPABILITY,
    PASSKEY_SIGNAL_OPTIONS_MAX,
    PASSKEY_SIGNAL_ACCEPTED_MAX,
    passkeySignalCapability,
    passkeySignalOptions,
    validPasskeySignalAck,
    validConditionalPasskeyEntry,
    validConditionalPasskeyList,
    base64URLEncode,
    base64URLDecode,
    validCredentialID,
    validPasskeyMetadata,
    validPasskeyMetadataList,
    PASSKEY_METADATA_LIMIT,
    validCredentialRevision,
    validAttachmentID,
    validAttachmentMetadata,
    validAttachmentList,
    safeFileName,
    validMimeType,
    base64Encode,
    base64Decode,
    attachmentStableKey,
    validClearFields,
    nativeOriginalFieldAny,
    generatePasswordString,
    looksLikeLocklarkSecret,
    pasteWarning,
    parseOTPAuthTOTP,
  };
})();
if (typeof module !== "undefined") module.exports = globalThis.LocklarkCore;
