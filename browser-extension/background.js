/* Native secrets stay in this worker; content scripts receive metadata only. */
if (typeof importScripts === "function") importScripts("core.js");
(() => {
  "use strict";
  const api = globalThis.browser || globalThis.chrome,
    core = globalThis.LocklarkCore;
  let quickFill = false,
    fillUnknown = false,
    pendingPasskey = null,
    passkeyConditionalSupported = false,
    passkeyUnknown = false,
    settings = core.normalizeSettings({}),
    autoLogin = true,
    offerSavePasskeys = true,
    offerUsePasskeys = true,
    offerSaveLogins = true,
    neverSaveOrigins = [],
    loginOverrides = {},
    watchtowerHIBP = false,
    generatorDefaults = {
      mode: "random",
      length: 24,
      digits: true,
      symbols: true,
      wordCount: 4,
      separator: "hyphens",
      capitalize: true,
      pinLength: 6,
    },
    lastMatchAt = 0,
    matchCategory = "login",
    vaultItems = [],
    vaultSearchGeneration = 0,
    detailCache = new Map(),
    pendingOpenAndFill = null,
    openAndFillTimer = null,
    hostCapabilities = [],
    attachmentUpload = null,
    checkoutPicker = null;
  const STAGED_TTL = 5 * 60 * 1000,
    LAST_FILLED_TTL = 60 * 1000,
    GENERATED_TTL = 5 * 60 * 1000,
    HISTORY_LIMIT = 20,
    MULTI_STEP_TTL = 120000,
    CHECKOUT_PICKER_TTL = 30000,
    CHECKOUT_MAX_FRAMES = 32,
    OTP_CAPTURE_TTL = 2 * 60 * 1000,
    OTP_CAPTURE_LIMIT = 8;
  const CONDITIONAL_INTENT_LIMIT = 64,
    CONDITIONAL_OPTIONS_MAX = 32768;
  // An ordinary (non-QuickFill) vault row opens the existing popup UI in a
  // persistent extension tab. The route is memory only: a fresh opaque token,
  // the exact item/revision, the source HTTPS tab and the native
  // capability/epoch it was created under. It never outlives its tab.
  const ROUTE_TTL = 2 * 60 * 1000,
    ROUTE_LIMIT = 4,
    // The only messages a route tab may send. Everything else is refused
    // before it reaches the ordinary popup handler.
    ROUTE_MESSAGE_TYPES = new Set([
      "route-claim",
      "route-copy-field",
      "item-get",
      "copy-field",
      "reveal-field",
      "fill",
      "otp",
      "open-and-fill",
      "route-close",
    ]);
  // Conditional (autofill) Passkey intents are metadata-only and never set
  // pendingPasskey: an unselected conditional request must not block ordinary
  // fill, save or OTP operations.
  const conditionalIntents = new Map(),
    stagedSaves = new Map(),
    lastFilledCredentials = new Map(),
    generatedHistory = [],
    multiStepSessions = new Map(),
    // Two-factor setup captures. Each entry holds the validated otpauth text
    // and the login candidates observed for one exact document; it is memory
    // only, bounded, expires after two minutes and is cleared on lock,
    // disconnect or a successful save.
    otpCaptures = new Map();
  function applySettings(raw) {
    settings = core.normalizeSettings(raw);
    autoLogin = settings.autoLogin;
    offerSavePasskeys = settings.offerSavePasskeys;
    offerUsePasskeys = settings.offerUsePasskeys;
    offerSaveLogins = settings.offerSaveLogins;
    loginOverrides = settings.loginOverrides;
    watchtowerHIBP = settings.watchtowerHIBP;
    neverSaveOrigins = [...settings.neverSaveOrigins];
    generatorDefaults = sanitizeGeneratorDefaults({
      ...settings.generatorDefaults,
      wordCount: generatorDefaults.wordCount,
      separator: generatorDefaults.separator,
      capitalize: generatorDefaults.capitalize,
      pinLength: generatorDefaults.pinLength,
    });
    refreshPasskeyConditionalSupport();
    applyIdleDetection();
    return settings;
  }
  function applyIdleDetection() {
    const minutes = settings.idleLockMinutes;
    try {
      if (minutes > 0)
        api.idle?.setDetectionInterval?.(Math.max(30, minutes * 60));
    } catch {}
  }
  const settingsReady = (async () => {
    try {
      applySettings(await api.storage?.local?.get?.(null));
    } catch {
      // A failed preference read must fail closed for automatic submission.
      autoLogin = false;
    }
  })();
  // The options page writes storage directly (it is not a popup sender), so
  // refresh the worker's in-memory copy when settings change there.
  try {
    api.storage?.onChanged?.addListener((changes, area) => {
      if (area !== "local" || !changes || typeof changes !== "object") return;
      const patch = {};
      for (const [key, change] of Object.entries(changes))
        if (change && typeof change === "object" && "newValue" in change)
          patch[key] = change.newValue;
      if (!Object.keys(patch).length) return;
      applySettings({ ...settings, ...patch });
      updateBadge();
      rebuildContextMenus();
    });
  } catch {}
  // Browser idle detection is advisory: a locked/idle profile locks the
  // native session only when the user opted in, and never unlocks anything.
  try {
    api.idle?.onStateChanged?.addListener((state) => {
      if (state === "active" || !(settings.idleLockMinutes > 0)) return;
      if (!capability) return;
      status = "空闲自动锁定";
      notify("Locklark 已锁定", "因空闲已自动锁定，请重新解锁。");
      lockVault();
    });
  } catch {}
  const NOTIFICATION_ICON =
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  function notify(title, message) {
    if (settings.notifications !== true) return;
    try {
      const result = api.notifications?.create?.({
        type: "basic",
        iconUrl: NOTIFICATION_ICON,
        title: String(title).slice(0, 120),
        message: String(message).slice(0, 300),
      });
      result?.catch?.(() => {});
    } catch {}
  }
  const PASSKEY_UNKNOWN = "Passkey 创建结果未确认，请检查金库和网站后再试";
  const FILL_UNKNOWN = "登录填充结果未确认，请核实页面；不会自动重试";
  let port = null,
    capability = "",
    hostState = "",
    context = null,
    rows = [],
    status = "未连接",
    pending = null,
    pendingOTP = null,
    otpCancellation = null,
    otpUnknown = false,
    epoch = 0,
    unconfirmedSave = false,
    watchtowerReport = null;
  // Per-tab ephemeral login continuation state. Metadata only, never field
  // values, and never persisted outside the service worker.
  const OTP_UNKNOWN = "验证码填充结果未确认，请核实页面";
  const SAVE_UNKNOWN = "结果未确认，请在金库核实，勿重复保存";
  const calls = new Map(),
    retired = new Set(),
    epochWaiters = new Set(),
    routeGrants = new Map(),
    routeTabs = new Map(),
    // Grants whose tabs.create() is still in flight. Browsers deliver the new
    // tab's onActivated/onUpdated before that promise resolves, so the tab id
    // is adopted from those events and never confused with an ordinary switch.
    routeBoots = new Set();
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
  function sanitizeOrigins(value) {
    if (!Array.isArray(value)) return [];
    const out = [];
    for (const origin of value.slice(0, 256)) {
      try {
        if (typeof origin === "string" && core.originFromURL(origin) === origin)
          if (!out.includes(origin)) out.push(origin);
      } catch {}
    }
    return out;
  }
  function sanitizeGeneratorDefaults(value) {
    const source = value && typeof value === "object" ? value : {};
    return {
      mode: ["random", "memorable", "pin"].includes(source.mode)
        ? source.mode
        : "random",
      length: Number.isSafeInteger(source.length) ? source.length : 24,
      digits: source.digits !== false,
      symbols: source.symbols !== false,
      wordCount: Number.isSafeInteger(source.wordCount) ? source.wordCount : 4,
      separator: typeof source.separator === "string" ? source.separator : "hyphens",
      capitalize: source.capitalize !== false,
      pinLength: Number.isSafeInteger(source.pinLength) ? source.pinLength : 6,
    };
  }
  function validCredentialText(value, allowEmpty = false) {
    return (
      typeof value === "string" &&
      (allowEmpty || value.length > 0) &&
      value.length <= 16384 &&
      value.isWellFormed()
    );
  }
  function zeroStaged(record) {
    if (!record) return;
    if (record.timer) clearTimeout(record.timer);
    record.timer = null;
    record.password = "";
  }
  function removeStaged(stageId) {
    const record = stagedSaves.get(stageId);
    if (!record) return null;
    zeroStaged(record);
    stagedSaves.delete(stageId);
    return record;
  }
  function clearStaged() {
    for (const record of stagedSaves.values()) zeroStaged(record);
    stagedSaves.clear();
  }
  // Generated plaintext is released by its own timer, not only by a later
  // visit to the popup or history. A released session never comes back: after
  // lock, disconnect, session reset or a resumed worker there is no entry.
  let generatedTimer = null,
    generatedTimerAt = 0;
  function clearGeneratedHistory() {
    if (generatedTimer) {
      clearTimeout(generatedTimer);
      generatedTimer = null;
    }
    generatedTimerAt = 0;
    for (const entry of generatedHistory) entry.password = "";
    generatedHistory.length = 0;
  }
  function releaseGenerated() {
    generatedTimer = null;
    generatedTimerAt = 0;
    pruneGenerated();
    scheduleGeneratedPrune();
  }
  function scheduleGeneratedPrune() {
    if (generatedTimer) clearTimeout(generatedTimer);
    generatedTimer = null;
    generatedTimerAt = 0;
    if (!generatedHistory.length) return;
    let next = Infinity;
    for (const entry of generatedHistory)
      if (Number.isSafeInteger(entry.expiresAt) && entry.expiresAt < next)
        next = entry.expiresAt;
    if (!Number.isFinite(next)) return;
    generatedTimerAt = next;
    generatedTimer = setTimeout(
      releaseGenerated,
      Math.max(0, Math.min(next - Date.now(), 24 * 60 * 60 * 1000)),
    );
    generatedTimer.unref?.();
  }
  function clearLastFilled() {
    for (const entry of lastFilledCredentials.values()) entry.password = "";
    lastFilledCredentials.clear();
  }
  function clearPrivateSessions() {
    clearStaged();
    clearGeneratedHistory();
    clearLastFilled();
  }
  function pruneGenerated(now = Date.now()) {
    for (let index = generatedHistory.length - 1; index >= 0; index--) {
      const entry = generatedHistory[index];
      if (now < entry.expiresAt) continue;
      entry.password = "";
      generatedHistory.splice(index, 1);
    }
  }
  // A worker that was suspended and resumed starts with an empty heap, so no
  // old entry can return and there is no timer to reuse. Discard any armed
  // deadline from a previous session and only arm one for live entries.
  function resumeGenerated() {
    if (generatedTimer) {
      clearTimeout(generatedTimer);
      generatedTimer = null;
    }
    generatedTimerAt = 0;
    pruneGenerated();
    scheduleGeneratedPrune();
  }
  resumeGenerated();

  // One-time card-fill authorizations. The popup, the inline menu and the
  // context menu mint only {v: 2, scope, at, nonce} synchronously inside a
  // trusted click. Claimed tab, frame or document ids are never accepted: the
  // worker binds each nonce to the context the browser reports for that same
  // request (the active tab for popup/menu requests, the message sender for
  // content frames). Each nonce is consumed exactly once within a short TTL,
  // and the injected frame receives a plain authorization flag, never the
  // nonce.
  const USER_GESTURE_TTL = 10 * 1000,
    GESTURE_REPLAY_LIMIT = 64;
  const consumedGestures = new Map(),
    gestureReplayOrder = [];
  function userGestureValid(value) {
    return (
      !!value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).sort().join(",") === "at,nonce,scope,v" &&
      value.v === 2 &&
      value.scope === "credit_card" &&
      typeof value.nonce === "string" &&
      /^[a-f0-9]{32}$/.test(value.nonce) &&
      Number.isSafeInteger(value.at) &&
      value.at > 0
    );
  }
  function forgetConsumedGestures(now = Date.now()) {
    while (
      gestureReplayOrder.length &&
      gestureReplayOrder[0].expiresAt <= now
    )
      consumedGestures.delete(gestureReplayOrder.shift().nonce);
  }
  // True only for a fresh, never-seen nonce bound to the browser-observed
  // context given by the caller; the nonce is recorded as consumed before
  // returning. Replays, stale, malformed or unbound values are refused and
  // consume nothing.
  function consumeUserGesture(value, c) {
    if (!userGestureValid(value) || !c) return false;
    const now = Date.now();
    if (value.at > now + 1000 || now - value.at > USER_GESTURE_TTL) return false;
    forgetConsumedGestures(now);
    if (consumedGestures.has(value.nonce)) return false;
    // The registry only holds nonces that still have time left, so a full
    // registry refuses this request rather than dropping a live nonce and
    // letting its replay through again.
    if (gestureReplayOrder.length >= GESTURE_REPLAY_LIMIT) return false;
    const record = {
      nonce: value.nonce,
      tabId: c.tabId,
      frameId: c.frameId || 0,
      documentId: c.documentId,
      expiresAt: value.at + USER_GESTURE_TTL,
    };
    consumedGestures.set(record.nonce, record);
    gestureReplayOrder.push(record);
    return true;
  }
  function pruneStaged() {
    const now = Date.now();
    for (const [stageId, record] of stagedSaves)
      if (!(now < record.expiresAt)) removeStaged(stageId);
    for (const [tabId, entry] of lastFilledCredentials)
      if (!(now < entry.expiresAt)) {
        entry.password = "";
        lastFilledCredentials.delete(tabId);
      }
    pruneGenerated(now);
  }
  function stagedForTab(tabId, origin) {
    pruneStaged();
    for (const record of stagedSaves.values())
      if (
        record.tabId === tabId &&
        record.origin === origin &&
        (record.mode === "new" || record.mode === "update")
      )
        return record;
    return null;
  }
  function serializeStaged(record) {
    if (!record) return null;
    return {
      stageId: record.stageId,
      origin: record.origin,
      username: record.username,
      title: record.title,
      mode: record.mode,
      existingItemId: record.existingItemId,
      existingRevision: record.existingRevision,
      expiresAt: record.expiresAt,
      connected: !!capability,
      candidates: rows
        .filter((row) => row.state === "active")
        .map((row) => ({ id: row.id, revision: row.revision, title: row.title })),
    };
  }
  function armStagedTimer(record) {
    record.timer = setTimeout(() => {
      if (stagedSaves.get(record.stageId) === record) removeStaged(record.stageId);
    }, Math.max(1, record.expiresAt - Date.now()));
  }
  function clearPendingOpenAndFill() {
    pendingOpenAndFill = null;
    if (openAndFillTimer) clearTimeout(openAndFillTimer);
    openAndFillTimer = null;
  }
  function publicItem(item) {
    return publicItemProjection(item, false);
  }
  function publicItemProjection(item, detailFrame) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    if (
      !/^[a-f0-9]{32}$/.test(item.id || "") ||
      !/^[a-f0-9]{64}$/.test(item.revision || "") ||
      typeof item.title !== "string" ||
      item.title.length > 1024
    )
      return null;
    const category = core.normalizeCategory(item.category) || "login";
    const urlObjects = [];
    for (const entry of Array.isArray(item.urls) ? item.urls.slice(0, 20) : []) {
      const raw = typeof entry === "string" ? entry : entry?.url;
      if (typeof raw !== "string" || !raw || raw.length > 8192) continue;
      if (!urlObjects.some((url) => url.url === raw)) urlObjects.push({ url: raw });
    }
    const urls = urlObjects.map((url) => url.url);
    const tags = Array.isArray(item.tags)
      ? item.tags
          .slice(0, 50)
          .filter((tag) => typeof tag === "string" && tag.length <= 128)
      : [];
    const passkey = publicPasskeyMetadata(item.passkey);
    // Per-credential arrays are detail-only and strictly bounded: a malformed,
    // duplicated or oversized list is refused instead of silently truncated to
    // its first credential. Leftover list rows never carry such an array.
    let passkeys = null;
    if (item.passkeys !== undefined) {
      if (!detailFrame) return null;
      passkeys = publicPasskeyList(item.passkeys);
      if (!passkeys) return null;
      if (
        passkey &&
        (passkeys.length !== 1 ||
          passkeys[0].credential_id !== passkey.credential_id)
      )
        return null;
    }
    let passkeyCount = passkeys
      ? passkeys.length
      : passkey
        ? 1
        : item.has_passkey === true
          ? 1
          : 0;
    if (item.passkey_count !== undefined) {
      if (
        !Number.isInteger(item.passkey_count) ||
        item.passkey_count < 0 ||
        item.passkey_count > core.PASSKEY_METADATA_LIMIT
      )
        return null;
      if (passkeys || passkey) {
        if (item.passkey_count !== passkeyCount) return null;
      } else {
        passkeyCount = item.passkey_count;
      }
    }
    const hasPasskey = passkeys
      ? passkeyCount > 0
      : passkeyCount > 0 || item.has_passkey === true;
    if (item.has_passkey === true && passkeyCount === 0 && item.passkey_count !== undefined)
      return null;
    return {
      id: item.id,
      revision: item.revision,
      category,
      title: item.title,
      subtitle:
        typeof item.subtitle === "string"
          ? item.subtitle.slice(0, 1024)
          : typeof item.username === "string"
            ? item.username.slice(0, 1024)
            : "",
      urls,
      url_objects: urlObjects,
      primary_url:
        typeof item.primary_url === "string"
          ? item.primary_url.slice(0, 8192)
          : urls[0] || "",
      tags,
      favorite: item.favorite === true,
      state: ["active", "archived", "trashed"].includes(item.state)
        ? item.state
        : "active",
      has_otp: item.has_otp === true,
      has_passkey: hasPasskey,
      ...(passkeys || item.passkey_count !== undefined
        ? { passkey_count: passkeyCount }
        : {}),
      ...(passkey ? { passkey } : {}),
      ...(passkeys ? { passkeys } : {}),
      updated_at:
        typeof item.updated_at === "string"
          ? item.updated_at.slice(0, 64)
          : "",
    };
  }
  function boundedString(value, length = 16384) {
    return typeof value === "string" ? value.slice(0, length) : "";
  }
  function publicPasskeyMetadata(raw) {
    if (!core.validPasskeyMetadata(raw)) return null;
    return {
      credential_id: raw.credential_id,
      rp_id: raw.rp_id,
      user_name: raw.user_name,
      display_name: raw.display_name,
      ...(raw.credential_revision !== undefined
        ? { credential_revision: raw.credential_revision }
        : {}),
    };
  }
  function publicPasskeyList(raw) {
    if (!core.validPasskeyMetadataList(raw)) return null;
    return raw.map((entry) => publicPasskeyMetadata(entry));
  }
  function publicDetail(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const meta = publicItemProjection(item, true);
    if (!meta) return null;
    const fields = [];
    const seen = new Set();
    const add = (field) => {
      if (!field || typeof field !== "object" || !field.id || seen.has(field.id)) return;
      seen.add(field.id);
      fields.push(field);
    };
    for (const field of core.flattenItemFields({ ...item, sections: [] }).slice(0, 200)) add(field);
    const detail = { ...meta, notes: "", username: "", fields, sections: [], attachments: [], identity: null, credit_card: null };
    detail.username = boundedString(item.username);
    if (detail.username)
      add({ id: "username", label: "用户名", type: "text", value: detail.username, concealed: false });
    if (item.has_password === true || typeof item.password === "string" && item.password)
      add({
        id: "password",
        label: "密码",
        type: "concealed",
        value: typeof item.password === "string" ? item.password : "",
        concealed: true,
        has_value: true,
        revealable: true,
      });
    if (item.has_notes === true || typeof item.notes === "string" && item.notes) {
      detail.notes = typeof item.notes === "string" ? boundedString(item.notes, 65536) : "";
      add({
        id: "notes",
        label: "备注",
        type: "concealed",
        value: detail.notes,
        concealed: true,
        has_value: true,
        revealable: true,
      });
    }
    if (item.has_otp === true || item.otp_code || typeof item.otp_secret === "string" && item.otp_secret)
      add({
        id: "otp",
        label: "一次性验证码",
        type: "totp",
        value: /^(?:[0-9]{6}|[0-9]{8})$/.test(item.otp_code || "") ? item.otp_code : "",
        concealed: false,
        has_value: true,
        revealable: true,
      });
    if (item.credit_card && typeof item.credit_card === "object") {
      const card = item.credit_card;
      detail.credit_card = card;
      if (card.cardholder_name) detail.cardholder = boundedString(card.cardholder_name, 256);
      if (card.type) detail.brand = boundedString(card.type, 64);
      if (card.expiry_date) detail.expiry = boundedString(card.expiry_date, 32);
      if (card.masked_number || card.last4)
        add({
          id: "cc-number",
          label: "卡号",
          type: "concealed",
          value: boundedString(card.masked_number || ("•••• " + card.last4), 64),
          concealed: true,
          has_value: true,
          revealable: true,
        });
      if (card.has_cvv === true)
        add({ id: "cc-csc", label: "安全码", type: "concealed", value: "", concealed: true, has_value: true, revealable: true });
      if (card.has_pin === true)
        add({ id: "cc-pin", label: "PIN", type: "concealed", value: "", concealed: true, has_value: true, revealable: true });
    }
    if (item.identity && typeof item.identity === "object") {
      detail.identity = item.identity;
      const map = {
        first_name: "first_name", middle_name: "middle_name", last_name: "last_name",
        birth_date: "birth_date", company: "company", title: "title", department: "department",
        job_title: "job_title", email: "email", phone: "phone", address_line1: "address1",
        address_line2: "address2", city: "city", state: "state", postal_code: "postal_code",
        country: "country", website: "website",
      };
      for (const [key, target] of Object.entries(map)) {
        if (typeof item.identity[key] !== "string" || !item.identity[key]) continue;
        detail[target] = boundedString(item.identity[key], 1024);
        add({ id: "identity:" + key, label: target, type: "text", value: detail[target], concealed: false });
      }
    }
    if (Array.isArray(item.sections))
      detail.sections = item.sections.slice(0, 20).map((section) => ({
        id: boundedString(section?.id, 128),
        title: boundedString(section?.title, 256),
        fields: (Array.isArray(section?.fields) ? section.fields : []).slice(0, 100).map((field) => {
          const concealed = field?.concealed === true || core.nativeFieldType(field?.type) === "concealed";
          const fieldID = "section:" + boundedString(section?.id, 128) + ":" + boundedString(field?.id, 128);
          add({
            id: fieldID,
            label: boundedString(field?.label, 256),
            type: core.nativeFieldType(field?.type),
            value: concealed ? "" : boundedString(field?.value),
            concealed,
            has_value: concealed && (field?.has_value === true || !!field?.value),
            revealable: concealed,
            section_id: boundedString(section?.id, 128),
            section_title: boundedString(section?.title, 256),
            purpose: boundedString(field?.purpose, 128),
          });
          return {
            id: boundedString(field?.id, 128),
            label: boundedString(field?.label, 256),
            type: core.nativeFieldType(field?.type),
            value: concealed ? "" : boundedString(field?.value),
            concealed,
            has_value: concealed && (field?.has_value === true || !!field?.value),
            purpose: boundedString(field?.purpose, 128),
          };
        }),
      }));
    if (Array.isArray(item.attachments)) {
      const seenAttachments = new Set();
      for (const entry of item.attachments.slice(0, 32)) {
        if (!core.validAttachmentMetadata(entry)) continue;
        if (seenAttachments.has(entry.id)) continue;
        seenAttachments.add(entry.id);
        const view = {
          id: entry.id,
          file_name: core.safeFileName(entry.file_name),
          size: entry.size,
          sha256: entry.sha256,
        };
        if (typeof entry.mime_type === "string" && entry.mime_type)
          view.mime_type = entry.mime_type;
        if (typeof entry.protected === "boolean") view.protected = entry.protected;
        detail.attachments.push(view);
      }
    }
    const passkey = publicPasskeyMetadata(item.passkey);
    if (passkey) detail.passkey = passkey;
    return detail;
  }
  function currentSiteFlags() {
    if (!context?.origin)
      return { disabledInline: false, neverSave: false };
    return {
      disabledInline: settings.disabledInlineMenuOrigins.includes(
        context.origin,
      ),
      neverSave: settings.neverSaveOrigins.includes(context.origin),
    };
  }
  function snapshot() {
    const site = currentSiteFlags();
    return {
      connected: !!capability,
      locked: !capability,
      autoLogin,
      quickFill,
      loginOverrides,
      offerSavePasskeys,
      offerUsePasskeys,
      showInlineMenu: settings.showInlineMenu,
      showToolbarBadgeCount: settings.showToolbarBadgeCount,
      openAndFillAutoSubmit: settings.openAndFillAutoSubmit,
      disabledInlineMenu: site.disabledInline,
      neverSave: site.neverSave,
      clipboardClearSeconds: settings.clipboardClearSeconds,
      theme: settings.theme,
      watchtowerHIBP,
      watchtower: watchtowerReport,
      status:
        status +
        (otpUnknown && !status.includes(OTP_UNKNOWN)
          ? " · " + OTP_UNKNOWN
          : "") +
        (fillUnknown && !status.includes(FILL_UNKNOWN)
          ? " · " + FILL_UNKNOWN
          : "") +
        (passkeyUnknown && !status.includes(PASSKEY_UNKNOWN)
          ? " · " + PASSKEY_UNKNOWN
          : ""),
      candidates: rows.map(candidateView),
      preferredItemId: multiStepFor(context?.tabId, context?.origin)?.itemId || "",
      preferredTitle: multiStepFor(context?.tabId, context?.origin)?.title || "",
      step: multiStepFor(context?.tabId, context?.origin)?.stepCompleted || "",
      hostState,
      hostOutdated: hostState === "outdated",
      attachmentsSupported: !!capability && core.attachmentCapability(hostCapabilities),
      nativeClipboard: nativeClipboardSupported(),
      passkeyManagementSupported: passkeyManagementSupported(),
      historySupported:
        !!capability && hostCapabilities.includes("history-v1"),
      checkoutFramesSupported: checkoutFramePolicy(),
      vaultItems: vaultItems.map((item) => ({ ...item })),
      pending: !!pending || !!pendingOTP || !!pendingPasskey,
      otpPending: !!pendingOTP,
      saveBlocked: unconfirmedSave,
      origin: context?.origin || "",
    };
  }
  function setBadge(text, color, title) {
    try {
      api.action?.setBadgeText?.({ text });
      if (color) api.action?.setBadgeBackgroundColor?.({ color });
      if (title) api.action?.setTitle?.({ title });
    } catch {}
  }
  function updateBadge() {
    if (!api.action) return;
    if (unconfirmedSave || otpUnknown || fillUnknown || passkeyUnknown) {
      setBadge("!", "#dc2626", "Locklark — 存在未确认操作");
      return;
    }
    if (!capability) {
      setBadge("L", "#d97706", "Locklark — 已锁定");
      return;
    }
    if (
      settings.showToolbarBadgeCount !== false &&
      rows.length > 0 &&
      context?.origin
    ) {
      const count = rows.length > 99 ? "99+" : String(rows.length);
      setBadge(count, "#0f766e", `Locklark — ${rows.length} 个匹配登录`);
      return;
    }
    setBadge("", "#0f766e", "Locklark — 已解锁");
  }
  function validCategory(value) {
    return ["login", "identity", "credit_card"].includes(value);
  }
  function rowCategory(row) {
    return row?.category || "login";
  }
  function wipeMap(value) {
    if (value && typeof value === "object")
      for (const key of Object.keys(value)) value[key] = "";
  }
  function multiStepFor(tabId, origin) {
    const session = multiStepSessions.get(tabId);
    if (!session) return null;
    if (Date.now() >= session.expiresAt) {
      multiStepSessions.delete(tabId);
      return null;
    }
    if (origin) {
      try {
        if (core.siteKey(origin) !== session.siteKey) {
          multiStepSessions.delete(tabId);
          return null;
        }
      } catch {
        multiStepSessions.delete(tabId);
        return null;
      }
    }
    return session;
  }
  function rememberStep(c, itemId, revision, title, step) {
    let site;
    try {
      site = core.siteKey(c.origin);
    } catch {
      return;
    }
    const previous = multiStepFor(c.tabId, c.origin);
    const stepCompleted =
      step === "username-only" ? "username" : "password";
    if (
      previous &&
      previous.itemId === itemId &&
      previous.stepCompleted === "password" &&
      stepCompleted === "username"
    )
      return;
    multiStepSessions.set(c.tabId, {
      tabId: c.tabId,
      windowId: c.windowId,
      siteKey: site,
      origin: c.origin,
      itemId,
      revision,
      title,
      stepCompleted,
      expiresAt: Date.now() + MULTI_STEP_TTL,
    });
  }
  function clear() {
    clearCheckoutPicker();
    if (pending?.injectionStarted) fillUnknown = true;
    if (pendingPasskey?.create) passkeyUnknown = true;
    pendingPasskey = null;
    quickFill = false;
    if (pendingOTP?.ackSent || pendingOTP?.injectionStarted) otpUnknown = true;
    otpCancellation = null;
    capability = "";
    context = null;
    rows = [];
    watchtowerReport = null;
    pending = null;
    pendingOTP = null;
    hostCapabilities = [];
    vaultItems = [];
    detailCache.clear();
    attachmentUpload = null;
    clearPendingOpenAndFill();
    matchCategory = "login";
    otpCaptures.clear();
    multiStepSessions.clear();
    clearConditionalIntentsWithNotify();
    refreshPasskeyConditionalSupport();
    invalidateClipboardGrants();
    revokeAllRoutes();
    advanceEpoch();
    for (const [requestId, c] of calls) {
      retired.add(requestId);
      clearTimeout(c.timer);
      c.reject(Error("refused"));
    }
    calls.clear();
    updateBadge();
    rebuildContextMenus();
  }
  function disconnect(preservePrivateSessions = false) {
    const p = port;
    port = null;
    clear();
    if (!preservePrivateSessions) clearPrivateSessions();
    if (p) p.disconnect();
  }
  function classifyNativeError(error) {
    const text = String(error?.message || error || "");
    if (
      /not found|no such native|specified native messaging host|native messaging host.*(missing|not installed)/i.test(
        text,
      )
    )
      return "missing";
    if (/forbidden|access to the specified native messaging host/i.test(text))
      return "forbidden";
    if (/exited|disconnected|terminated|closed/i.test(text)) return "exited";
    return "error";
  }
  function nativeGuidanceText(code) {
    return (
      {
        missing:
          "未找到 Locklark 原生宿主：请重新安装桌面端，或运行 locklark-browser-register 注册后重试",
        forbidden:
          "浏览器拒绝了这个原生宿主：请重新运行注册命令并确认清单路径",
        exited: "Locklark 原生宿主已退出：请确认桌面端已安装并重新连接",
        timeout:
          "等待 Locklark 解锁超时：请在 Locklark 窗口中完成解锁后重试",
        outdated:
          "Locklark 原生宿主版本过旧，请升级桌面端后重新连接",
        error: "无法连接 Locklark 原生宿主，请重新连接",
      }[code] || "无法连接 Locklark 原生宿主，请重新连接"
    );
  }
  function disconnectWithStatus(message) {
    disconnect();
    status = unconfirmedSave
      ? SAVE_UNKNOWN
      : otpUnknown
        ? message + " · " + OTP_UNKNOWN
        : message;
  }
  function menuCreate(options) {
    try {
      api.contextMenus?.create?.(options);
    } catch {}
  }
  function menuRemoveAll() {
    try {
      api.contextMenus?.removeAll?.();
    } catch {}
  }
  function menuItems(category) {
    return vaultItems
      .filter((item) => item.category === category)
      .slice(0, 10);
  }
  function rebuildContextMenus() {
    if (!api.contextMenus || typeof api.contextMenus.create !== "function")
      return;
    menuRemoveAll();
    menuCreate({
      id: "locklark-root",
      title: "Locklark",
      contexts: ["page", "editable"],
    });
    if (!capability) {
      menuCreate({
        id: "locklark-connect",
        parentId: "locklark-root",
        title: "解锁 Locklark…",
        contexts: ["page", "editable"],
      });
      menuCreate({
        id: "locklark-options",
        parentId: "locklark-root",
        title: "扩展设置…",
        contexts: ["page", "editable"],
      });
      return;
    }
    for (const [id, title, category] of [
      ["fill-login", "填充登录", "login"],
      ["fill-identity", "填充身份信息", "identity"],
      ["fill-card", "填充银行卡", "card"],
    ]) {
      menuCreate({
        id,
        parentId: "locklark-root",
        title,
        contexts: ["page", "editable"],
      });
      const matches =
        category === "login"
          ? rows.slice(0, 10).map((row) => ({
              id: row.id,
              revision: row.revision,
              title: row.title,
            }))
          : menuItems(category);
      if (!matches.length)
        menuCreate({
          id: id + "-empty",
          parentId: id,
          title:
            category === "login"
              ? "（当前网站无匹配登录）"
              : "（暂无可用条目）",
          enabled: false,
          contexts: ["page", "editable"],
        });
      for (const item of matches)
        menuCreate({
          id: `${id}:${item.id}:${item.revision}`,
          parentId: id,
          title: (item.title || "（无标题）").slice(0, 64),
          contexts: ["page", "editable"],
        });
    }
    menuCreate({
      id: "generate-password",
      parentId: "locklark-root",
      title: "生成并填充新密码",
      contexts: ["editable"],
    });
    menuCreate({
      id: "save-login",
      parentId: "locklark-root",
      title: "保存当前页面登录",
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "context-separator-1",
      parentId: "locklark-root",
      type: "separator",
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "locklark-toggle-site-inline",
      parentId: "locklark-root",
      title: "在此网站停用快捷菜单",
      type: "checkbox",
      checked: currentSiteFlags().disabledInline,
      contexts: ["page", "editable"],
    });
    menuCreate({
      id: "lock-vault",
      parentId: "locklark-root",
      title: "立即锁定 Locklark",
      contexts: ["all"],
    });
    menuCreate({
      id: "locklark-options",
      parentId: "locklark-root",
      title: "扩展设置…",
      contexts: ["all"],
    });
  }
  function openOptions() {
    try {
      const result = api.runtime.openOptionsPage?.();
      if (result && typeof result.catch === "function") result.catch(() => {});
    } catch {}
  }
  // The same 32-hex nonce the popup and inline menu mint inside a click.
  function menuNonce() {
    return [...crypto.getRandomValues(new Uint8Array(16))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  function contextMenuClicked(info, menuTab) {
    const id = typeof info?.menuItemId === "string" ? info.menuItemId : "";
    if (id === "locklark-connect") {
      void connect();
      return;
    }
    if (id === "locklark-options") {
      openOptions();
      return;
    }
    if (id === "lock-vault") {
      void lockVault();
      return;
    }
    if (id === "save-login") {
      void save();
      return;
    }
    if (id === "generate-password") {
      void generateAndFill();
      return;
    }
    if (id === "locklark-toggle-site-inline") {
      void toggleSiteInline();
      return;
    }
    const [kind, itemId, revision] = id.split(":");
    if (!/^[a-f0-9]{32}$/.test(itemId || "")) return;
    if (!/^[a-f0-9]{64}$/.test(revision || "")) return;
    if (kind === "fill-login") {
      const row = rows.find(
        (candidate) =>
          candidate.id === itemId && candidate.revision === revision,
      );
      if (row) void fill(itemId, revision);
      return;
    }
    if (kind === "fill-identity") {
      void fillItemCategory(itemId, revision, "identity");
      return;
    }
    if (kind === "fill-card") {
      // The context-menu click is a trusted click the worker itself receives;
      // the menu branch mints the same at+nonce proof on that click and binds
      // it to the tab Chrome reports for that click through fillItemCategory.
      const userGesture = {
        v: 2,
        scope: "credit_card",
        at: Date.now(),
        nonce: menuNonce(),
      };
      const clickedTab =
        menuTab &&
        typeof menuTab === "object" &&
        !Array.isArray(menuTab) &&
        Number.isSafeInteger(menuTab.id) &&
        menuTab.id > 0 &&
        Number.isSafeInteger(menuTab.windowId) &&
        menuTab.windowId > 0
          ? { id: menuTab.id, windowId: menuTab.windowId }
          : null;
      void fillItemCategory(itemId, revision, "card", userGesture, clickedTab);
    }
  }
  function commandInvoked(command) {
    if (command === "autofill" || command === "autofill-current-tab") {
      void autofillActiveTab();
      return;
    }
    if (command === "lock" || command === "lock-vault") lockVault();
  }
  try {
    api.commands?.onCommand?.addListener(commandInvoked);
  } catch {}
  try {
    api.contextMenus?.onClicked?.addListener(contextMenuClicked);
  } catch {}
  try {
    api.runtime.onInstalled?.addListener(() => {
      rebuildContextMenus();
      updateBadge();
    });
  } catch {}
  function startCall(type, requestId, timeout) {
    let resolve, reject;
    const promise = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const timer = setTimeout(() => {
      calls.delete(requestId);
      const error = Error("refused");
      error.timeout = true;
      reject(error);
      disconnectWithStatus("连接或请求已过期，请重新连接");
    }, timeout);
    calls.set(requestId, { resolve, reject, timer, type });
    return promise;
  }
  function request(type, fields = {}, timeout = 35000, requestId = id()) {
    if (!port) return Promise.reject(Error("refused"));
    const promise = startCall(type, requestId, timeout);
    try {
      port.postMessage({ v: 1, id: requestId, type, ...fields });
    } catch {
      const call = calls.get(requestId);
      if (call) {
        clearTimeout(call.timer);
        calls.delete(requestId);
        call.reject(Error("refused"));
      }
    } finally {
      if (Object.hasOwn(fields, "username")) fields.username = "";
      if (Object.hasOwn(fields, "password")) fields.password = "";
      if (Object.hasOwn(fields, "item_json")) fields.item_json = "";
    }
    return promise;
  }
  // Browser-observed identity of the active tab and its top document (and of
  // the sender frame when frameId > 0).
  async function captureTopDocument(frameId = 0) {
    if (!Number.isSafeInteger(frameId) || frameId < 0) throw Error("refused");
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    if (
      tabs.length !== 1 ||
      !Number.isSafeInteger(tabs[0].id) ||
      tabs[0].id < 1 ||
      !Number.isSafeInteger(tabs[0].windowId) ||
      tabs[0].windowId < 1
    )
      throw Error("refused");
    const tab = tabs[0],
      topOrigin = core.originFromURL(tab.url);
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
      results[0].result.origin !== topOrigin
    )
      throw Error("refused");
    const topDocumentId = results[0].documentId;
    let origin = topOrigin,
      documentId = topDocumentId;
    if (frameId > 0) {
      const frames = await api.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frameId] },
        func: core.probe,
      });
      if (
        frames.length !== 1 ||
        frames[0].frameId !== frameId ||
        typeof frames[0].documentId !== "string" ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(frames[0].documentId) ||
        frames[0].result?.top !== false ||
        core.originFromURL(frames[0].result?.origin) !== topOrigin
      )
        throw Error("refused");
      origin = core.originFromURL(frames[0].result.origin);
      documentId = frames[0].documentId;
    }
    const again = await api.tabs.query({ active: true, currentWindow: true });
    if (
      again.length !== 1 ||
      again[0].id !== tab.id ||
      again[0].windowId !== tab.windowId ||
      core.originFromURL(again[0].url) !== topOrigin
    )
      throw Error("refused");
    return {
      tabId: tab.id,
      windowId: tab.windowId,
      origin,
      // The exact top-level URL the browser reported for this capture. A
      // route is bound to it, so any later path/query/fragment change ends
      // the route even when the origin is unchanged. Never sent to native:
      // fields() whitelists only capability/origin/tab/document.
      url: tab.url,
      documentId,
      frameId,
      topDocumentId,
      topOrigin,
    };
  }
  // Explicit checkout-frame selection is public metadata only: one bounded
  // list of the HTTPS frames the browser actually injected into. No card
  // field is read, returned or cached until the native owner approves the
  // exact frozen target later.
  function checkoutFramePolicy() {
    return (
      !!capability &&
      typeof core.checkoutProbe === "function" &&
      typeof core.fillCheckoutCardDocument === "function" &&
      hostCapabilities.includes("checkout-frames-v1")
    );
  }
  function canonicalHTTPSOrigin(value) {
    if (typeof value !== "string" || !value || value.length > 2048) return "";
    try {
      if (!core.validHTTPSOrigin(value)) return "";
      return core.originFromURL(value) === value ? value : "";
    } catch {
      return "";
    }
  }
  function checkoutDocumentID(value) {
    return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  }
  function checkoutProbeResultValid(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    if (
      Object.keys(value).sort().join(",") !==
      "document_stable,fence_present,origin,sandbox_ever,secure,top"
    )
      return false;
    return (
      canonicalHTTPSOrigin(value.origin) === value.origin &&
      typeof value.top === "boolean" &&
      value.secure === true &&
      value.fence_present === true &&
      value.document_stable === true &&
      value.sandbox_ever === false
    );
  }
  async function checkoutCaptureFrames() {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    if (!Array.isArray(tabs) || tabs.length !== 1) throw Error("refused");
    const tab = tabs[0];
    if (
      !Number.isSafeInteger(tab?.id) || tab.id < 1 ||
      !Number.isSafeInteger(tab?.windowId) || tab.windowId < 1
    )
      throw Error("refused");
    const topOrigin = canonicalHTTPSOrigin(core.originFromURL(tab.url));
    if (!topOrigin) throw Error("refused");
    const results = await api.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      func: core.checkoutProbe,
    });
    if (
      !Array.isArray(results) || results.length < 1 ||
      results.length > CHECKOUT_MAX_FRAMES
    )
      throw Error("refused");
    const frames = [],
      frameIds = new Set(),
      documentIds = new Set();
    let top = null;
    for (const entry of results) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry))
        throw Error("refused");
      const frameId = entry.frameId,
        documentId = entry.documentId,
        result = entry.result;
      if (!Number.isSafeInteger(frameId) || frameId < 0) throw Error("refused");
      if (!checkoutDocumentID(documentId) || !checkoutProbeResultValid(result))
        throw Error("refused");
      if (frameIds.has(frameId) || documentIds.has(documentId))
        throw Error("refused");
      frameIds.add(frameId);
      documentIds.add(documentId);
      if (result.top) {
        if (frameId !== 0 || top) throw Error("refused");
        top = { frameId, documentId, origin: result.origin, top: true };
      } else {
        if (frameId === 0) throw Error("refused");
        frames.push({ frameId, documentId, origin: result.origin, top: false });
      }
    }
    if (!top || top.origin !== topOrigin) throw Error("refused");
    const again = await api.tabs.query({ active: true, currentWindow: true });
    if (
      !Array.isArray(again) || again.length !== 1 ||
      again[0]?.id !== tab.id || again[0]?.windowId !== tab.windowId ||
      canonicalHTTPSOrigin(core.originFromURL(again[0]?.url)) !== topOrigin
    )
      throw Error("refused");
    return {
      tabId: tab.id,
      windowId: tab.windowId,
      topOrigin,
      topDocumentId: top.documentId,
      frames: [top, ...frames],
    };
  }
  function checkoutFrameSignature(capture) {
    return JSON.stringify({
      tabId: capture.tabId,
      windowId: capture.windowId,
      topOrigin: capture.topOrigin,
      topDocumentId: capture.topDocumentId,
      frames: capture.frames.map((frame) => [
        frame.frameId,
        frame.documentId,
        frame.origin,
        frame.top,
      ]),
    });
  }
  function clearCheckoutPicker() {
    const picker = checkoutPicker;
    checkoutPicker = null;
    if (picker?.timer) clearTimeout(picker.timer);
  }
  function checkoutPickerView(picker) {
    return {
      nonce: picker.nonce,
      topOrigin: picker.topOrigin,
      expiresAt: picker.expiresAt,
      candidates: [...picker.candidates.values()].map((entry) => ({
        choice: entry.choice,
        origin: entry.origin,
        frameId: entry.frameId,
        top: entry.top,
      })),
    };
  }
  async function startCheckoutPicker(message) {
    if (Object.keys(message).sort().join(",") !== "id,revision,type,userGesture")
      throw Error("refused");
    if (
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    // The popup only supplies the nonce. The tab, its top frame and the
    // nonce's age all come from the browser below.
    const userGesture = message.userGesture;
    // A new picker always invalidates the previous public choice set.
    clearCheckoutPicker();
    if (!capability || pending || pendingOTP || pendingPasskey)
      throw Error("refused");
    if (!checkoutFramePolicy()) {
      status = "当前原生宿主或浏览器不支持选择结账表单";
      throw Error("refused");
    }
    const generation = epoch,
      expectedCapability = capability;
    // Freeze the exact top document now; a picker started for a page that was
    // already replaced is useless and must not inherit this tab's grant.
    // The top document is identity-checked by the bounded all-frame probe
    // below, which also proves the tab did not change mid-enumeration.
    const frozenCapture = await captureTopDocument(0);
    if (generation !== epoch || capability !== expectedCapability)
      throw Error("refused");
    if (!consumeUserGesture(userGesture, frozenCapture)) {
      clearCheckoutPicker();
      throw Error("refused");
    }
    const item = await getVaultItem(message.id, message.revision);
    if (
      !item ||
      item.id !== message.id ||
      item.revision !== message.revision ||
      core.normalizeCategory(item.category) !== "card" ||
      item.unavailable ||
      item.readOnly
    )
      throw Error("refused");
    if (generation !== epoch || capability !== expectedCapability)
      throw Error("refused");
    const capture = await checkoutCaptureFrames();
    if (
      generation !== epoch ||
      capability !== expectedCapability ||
      capture.tabId !== frozenCapture.tabId ||
      capture.windowId !== frozenCapture.windowId ||
      capture.topDocumentId !== frozenCapture.topDocumentId
    )
      throw Error("refused");
    const candidates = new Map();
    for (const frame of capture.frames) {
      const choice = id();
      candidates.set(choice, {
        choice,
        frameId: frame.frameId,
        documentId: frame.documentId,
        origin: frame.origin,
        top: frame.frameId === 0,
      });
    }
    if (candidates.size < 1 || candidates.size > CHECKOUT_MAX_FRAMES)
      throw Error("refused");
    const nonce = id(),
      expiresAt = Date.now() + CHECKOUT_PICKER_TTL;
    const picker = {
      nonce,
      epoch: generation,
      capability: expectedCapability,
      itemId: message.id,
      revision: message.revision,
      tabId: capture.tabId,
      windowId: capture.windowId,
      topOrigin: capture.topOrigin,
      topDocumentId: capture.topDocumentId,
      signature: checkoutFrameSignature(capture),
      userAuthorized: userGesture,
      candidates,
      createdAt: Date.now(),
      expiresAt,
      timer: null,
    };
    picker.timer = setTimeout(() => {
      if (checkoutPicker !== picker) return;
      checkoutPicker = null;
      status = "选择结账表单已过期，请重新选择";
      updateBadge();
    }, CHECKOUT_PICKER_TTL);
    checkoutPicker = picker;
    status = "请选择要填充的结账表单来源；不会自动选择";
    updateBadge();
    return checkoutPickerView(picker);
  }
  function consumeCheckoutChoice(message) {
    if (Object.keys(message).sort().join(",") !== "choice,id,nonce,revision,type")
      return null;
    if (
      !/^[a-f0-9]{32}$/.test(message.nonce || "") ||
      !/^[a-f0-9]{32}$/.test(message.choice || "") ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      return null;
    const picker = checkoutPicker;
    if (
      !picker ||
      picker.nonce !== message.nonce ||
      picker.itemId !== message.id ||
      picker.revision !== message.revision ||
      picker.epoch !== epoch ||
      picker.capability !== capability ||
      // The picker's own TTL alone governs selection; a consumed gesture does
      // not retire the list the user is looking at.
      Date.now() > picker.expiresAt
    ) {
      clearCheckoutPicker();
      return null;
    }
    if (pending || pendingOTP || pendingPasskey) return null;
    const entry = picker.candidates.get(message.choice);
    if (!entry) return null;
    // Consume exactly once before any asynchronous native request.
    clearCheckoutPicker();
    return { picker, entry };
  }
  async function selectCheckout(message) {
    const chosen = consumeCheckoutChoice(message);
    if (!chosen) throw Error("refused");
    status = "已选择结账表单，正在核对当前页面";
    // The picker exists only because a fresh one-time gesture was consumed for
    // its exact tab/document. The grant is detached from any replayable request
    // value and can authorize only this one crossing of the async gap.
    const grant = Object.freeze({
      nonce: chosen.picker.userAuthorized.nonce,
      tabId: chosen.picker.tabId,
      windowId: chosen.picker.windowId,
      documentId: chosen.picker.topDocumentId,
    });
    void checkoutFill(chosen.picker, chosen.entry, grant).catch(() => {});
    return true;
  }
  function cancelCheckoutPickerMessage(message) {
    if (Object.keys(message).sort().join(",") !== "nonce,type")
      throw Error("refused");
    if (!/^[a-f0-9]{32}$/.test(message.nonce || "")) throw Error("refused");
    if (checkoutPicker?.nonce !== message.nonce) return false;
    clearCheckoutPicker();
    status = "已取消本次填充";
    return true;
  }
  function stopCheckoutMonitor(intent) {
    if (intent?.monitor) {
      clearTimeout(intent.monitor);
      intent.monitor = null;
    }
  }
  // Native generic cancellation is allowed only while this exact intent still
  // owns the single pending slot and no OTP or Passkey approval is in flight.
  function cancelOwnCheckoutNative(intent) {
    if (
      pending !== intent ||
      pendingOTP ||
      pendingPasskey ||
      intent.cancelSent ||
      !capability
    )
      return;
    intent.cancelSent = true;
    void request("cancel", { capability }).catch(() => {});
  }
  function markCheckoutStale(intent, generation) {
    stopCheckoutMonitor(intent);
    intent.stale = true;
    if (generation !== epoch || pending !== intent) return;
    cancelOwnCheckoutNative(intent);
    pending = null;
    context = null;
    rows = [];
    advanceEpoch();
    status = "结账页面已变化，本次填充已取消";
    updateBadge();
    rebuildContextMenus();
  }
  // One bounded monitor per chosen context. It only observes public frame
  // identity; any child navigation, document replacement, tab switch or lock
  // invalidates the native approval before it can release card fields.
  function watchCheckoutContext(intent, generation) {
    const tick = async () => {
      intent.monitor = null;
      if (generation !== epoch || pending !== intent || intent.stale) return;
      if (Date.now() > intent.monitorUntil) {
        markCheckoutStale(intent, generation);
        return;
      }
      try {
        const capture = await checkoutCaptureFrames();
        if (generation !== epoch || pending !== intent || intent.stale) return;
        if (checkoutFrameSignature(capture) !== intent.signature) {
          markCheckoutStale(intent, generation);
          return;
        }
      } catch {
        markCheckoutStale(intent, generation);
        return;
      }
      if (generation === epoch && pending === intent && !intent.stale)
        intent.monitor = setTimeout(tick, 750);
    };
    intent.monitor = setTimeout(tick, 750);
  }
  async function checkoutRevalidate(intent, generation) {
    if (generation !== epoch || pending !== intent || intent.stale)
      throw Error("refused");
    const capture = await checkoutCaptureFrames();
    if (generation !== epoch || pending !== intent || intent.stale)
      throw Error("refused");
    if (checkoutFrameSignature(capture) !== intent.signature)
      throw Error("refused");
    const target = capture.frames.find(
      (frame) => frame.frameId === intent.frameId,
    );
    if (
      !target ||
      target.documentId !== intent.documentId ||
      target.origin !== intent.origin ||
      target.top !== (intent.frameId === 0) ||
      capture.topOrigin !== intent.topOrigin ||
      capture.topDocumentId !== intent.topDocumentId ||
      capture.tabId !== intent.tabId ||
      capture.windowId !== intent.windowId
    )
      throw Error("refused");
    return capture;
  }
  function checkoutWireFields(intent) {
    const payload = {
      ...fields(intent),
      profile_kind: "credit_card",
    };
    if (intent.checkout) payload.checkout = { ...intent.checkout };
    return payload;
  }
  async function checkoutMatch(intent, generation) {
    await checkoutRevalidate(intent, generation);
    const response = await request("match-profiles", checkoutWireFields(intent), 35000);
    if (generation !== epoch || pending !== intent || intent.stale)
      throw Error("refused");
    if (
      !response ||
      response.type !== "profiles" ||
      !Array.isArray(response.profiles) ||
      response.profiles.length > 100
    )
      throw Error("refused");
    const profile = response.profiles.find(
      (row) =>
        row &&
        row.id === intent.itemId &&
        row.revision === intent.revision &&
        row.category === "credit_card",
    );
    if (!profile) throw Error("refused");
    return profile;
  }
  async function checkoutFill(picker, target, grant = null) {
    const generation = epoch;
    if (pending || pendingOTP || pendingPasskey) throw Error("refused");
    // The picker can only exist after a fresh gesture was consumed for it; the
    // caller must pass the exact frozen grant derived from that consumption.
    if (
      !grant ||
      !Object.isFrozen(grant) ||

      grant.nonce !== picker?.userAuthorized?.nonce ||
      grant.tabId !== picker?.tabId ||
      grant.windowId !== picker?.windowId ||
      grant.documentId !== picker?.topDocumentId ||
      !picker.topDocumentId
    )
      throw Error("refused");
    const intent = {
      kind: "checkout",
      itemId: picker.itemId,
      revision: picker.revision,
      tabId: picker.tabId,
      windowId: picker.windowId,
      frameId: target.frameId,
      documentId: target.documentId,
      origin: target.origin,
      topOrigin: picker.topOrigin,
      topDocumentId: picker.topDocumentId,
      signature: picker.signature,
      // The optional native checkout object is proposed only for a target
      // frame that is neither the top document nor the top origin. Native PSL
      // policy remains the authority on whether that proposal is acceptable.
      checkout:
        target.frameId > 0 && target.origin !== picker.topOrigin
          ? {
              top_origin: picker.topOrigin,
              top_document_id: picker.topDocumentId,
              frame_id: target.frameId,
            }
          : null,
      requestId: "",
      sent: false,
      cancelSent: false,
      injectionStarted: false,
      stale: false,
      monitor: null,
      monitorUntil: Date.now() + 35000,
    };
    pending = intent;
    context = {
      tabId: intent.tabId,
      windowId: intent.windowId,
      frameId: intent.frameId,
      documentId: intent.documentId,
      origin: intent.origin,
      topOrigin: intent.topOrigin,
      topDocumentId: intent.topDocumentId,
    };
    // The choice is only consumed; the exact page and the native profile set
    // are still being revalidated, so do not imply an approval already exists.
    status = "正在核对所选结账表单页面";
    updateBadge();
    rebuildContextMenus();
    let response = null;
    try {
      await checkoutMatch(intent, generation);
      await checkoutRevalidate(intent, generation);
      if (generation !== epoch || pending !== intent || intent.stale)
        throw Error("refused");
      intent.requestId = id();
      intent.sent = true;
      // Only now is the cross-site or same-site target actually proposed to the
      // native owner, which may require an in-window approval.
      status = "请在原生窗口核对两个网站来源并批准本次结账表单填充";
      updateBadge();
      watchCheckoutContext(intent, generation);
      response = await request(
        "fill-profile",
        {
          ...fields(intent),
          item_id: intent.itemId,
          revision: intent.revision,
          ...(intent.checkout ? { checkout: { ...intent.checkout } } : {}),
        },
        35000,
        intent.requestId,
      );
      stopCheckoutMonitor(intent);
      if (generation !== epoch || pending !== intent || intent.stale)
        throw Error("refused");
      const fill = response?.profile_fill;
      if (
        !fill ||
        typeof fill !== "object" ||
        Array.isArray(fill) ||
        fill.item_id !== intent.itemId ||
        fill.revision !== intent.revision ||
        fill.category !== "credit_card" ||
        !fill.fields ||
        typeof fill.fields !== "object" ||
        Array.isArray(fill.fields)
      )
        throw Error("refused");
      // Bind the approval to the live page again before the single exact-document
      // injection. The native values never leave this scope.
      await checkoutRevalidate(intent, generation);
      if (generation !== epoch || pending !== intent || intent.stale)
        throw Error("refused");
      intent.injectionStarted = true;
      let results;
      try {
        results = await api.scripting.executeScript({
          target: { tabId: intent.tabId, documentIds: [intent.documentId] },
          func: core.fillCheckoutCardDocument,
          args: [
            intent.origin,
            fill.fields,
            Date.now() + 1500,
            intent.frameId === 0,
            true,
          ],
        });
      } finally {
        wipeMap(fill.fields);
        if (response.profile_fill) {
          wipeMap(response.profile_fill.fields);
          response.profile_fill.fields = {};
        }
      }
      const result = results?.length === 1 ? results[0]?.result : null;
      if (
        generation !== epoch ||
        pending !== intent ||
        intent.stale ||
        !Array.isArray(results) ||
        results.length !== 1 ||
        results[0].frameId !== intent.frameId ||
        results[0].documentId !== intent.documentId ||
        !result ||
        typeof result !== "object" ||
        Array.isArray(result) ||
        Object.keys(result).sort().join(",") !== "count,filled" ||
        result.filled !== true ||
        !Number.isSafeInteger(result.count) ||
        result.count < 1 ||
        result.count > CHECKOUT_MAX_FRAMES
      )
        throw Error("refused");
      intent.injectionStarted = false;
      fillUnknown = false;
      status = "本次已请求填充结账表单；未自动提交；请核实网站结果";
    } catch {
      if (generation === epoch && pending === intent) {
        fillUnknown = intent.injectionStarted === true;
        status = fillUnknown
          ? FILL_UNKNOWN
          : intent.stale
            ? "结账页面已变化，本次填充已取消"
            : "本次结账表单填充未完成；未自动重试";
      }
    } finally {
      stopCheckoutMonitor(intent);
      if (response?.profile_fill) {
        if (response.profile_fill.fields) wipeMap(response.profile_fill.fields);
        response.profile_fill.fields = {};
      }
      if (generation === epoch && pending === intent) {
        pending = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  async function activeSite() {
    try {
      const tabs = await api.tabs.query({ active: true, currentWindow: true });
      if (!Array.isArray(tabs) || tabs.length !== 1)
        return { origin: "", unsecured: false };
      return (
        core.siteFromURL(tabs[0]?.url) || { origin: "", unsecured: false }
      );
    } catch {
      return { origin: "", unsecured: false };
    }
  }
  function candidateView(row) {
    const view = {
      id: row.id,
      title: row.title,
      revision: row.revision,
      category: rowCategory(row),
      ...(row.subtitle ? { subtitle: row.subtitle } : {}),
    };
    if (Array.isArray(row.watchtower_flags))
      view.watchtower_flags = [...row.watchtower_flags];
    for (const key of [
      "strength_score",
      "strength_category",
      "reuse_count",
      "breach_count",
    ])
      if (row[key] !== undefined) view[key] = row[key];
    return view;
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
    const now = await captureTopDocument(expected.frameId || 0);
    if (!core.sameContext(expected, now)) throw Error("refused");
  }
  async function runWatchtower(message) {
    await settingsReady;
    if (!capability) {
      status = "请先连接原生金库，再运行 Watchtower 安全体检";
      return;
    }
    if (pending || pendingOTP || pendingPasskey) throw Error("refused");
    const generation = epoch;
    let c = context;
    if (!c) {
      try {
        c = await captureTopDocument();
      } catch {
        if (generation !== epoch) throw Error("refused");
        const site = await activeSite();
        status = site.unsecured
          ? "当前网页使用不安全的 HTTP 连接，Watchtower 需要 HTTPS 页面；未发送 HIBP 查询"
          : "无法读取当前网页，请打开 HTTPS 登录页后重试";
        return;
      }
    }
    if (generation !== epoch) throw Error("refused");
    await current(c);
    if (generation !== epoch) throw Error("refused");
    const includeHibp = watchtowerHIBP === true && message.includeHibp === true;
    status = includeHibp
      ? "正在运行本地与 HIBP Watchtower 安全体检"
      : "正在运行本地 Watchtower 安全体检";
    const response = await request(
      "watchtower",
      { ...fields(c), include_hibp: includeHibp },
      includeHibp ? 65000 : 35000,
    );
    if (generation !== epoch) throw Error("refused");
    if (!response || !core.validWatchtower(response.watchtower))
      throw Error("refused");
    watchtowerReport = response.watchtower;
    status =
      includeHibp && watchtowerReport.hibp_error === "unavailable"
        ? "HIBP 泄露库暂不可用，已显示本地体检结果"
        : `Watchtower 体检完成 · 安全评分 ${watchtowerReport.overall_score}/100`;
  }
  async function openWatchtower(origin) {
    if (!core.validHTTPSOrigin(origin)) throw Error("refused");
    const site = await activeSite();
    let allowed = false;
    if (site.origin === origin || context?.origin === origin) allowed = true;
    if (watchtowerReport) {
      if (watchtowerReport.site?.origin === origin) allowed = true;
      for (const finding of [
        ...watchtowerReport.site_findings,
        ...watchtowerReport.findings,
      ])
        if (finding.origin === origin) {
          allowed = true;
          break;
        }
    }
    if (!allowed || typeof api.tabs.create !== "function")
      throw Error("refused");
    await api.tabs.create({ url: origin });
    status = "已打开网站，请更新登录密码";
  }
  // Safari's runtime.connectNative does not provide the duplex stdio Port, so
  // the Safari build supplies an explicit connector in its background-only
  // namespace script. Chromium and Firefox keep calling their own
  // api.runtime.connectNative unchanged; nothing is patched globally.
  function nativeConnect() {
    const shim = globalThis.LocklarkSafariNativePort;
    if (
      shim &&
      typeof shim.connectNative === "function" &&
      typeof shim.isSafariRuntime === "function" &&
      shim.isSafariRuntime(api)
    )
      return shim.connectNative(api, "org.locklark.browser");
    return api.runtime.connectNative("org.locklark.browser");
  }
  async function connect() {
    disconnect(true);
    unconfirmedSave = false;
    retired.clear();
    status = "请在原生窗口解锁并确认连接";
    let p;
    try {
      p = nativeConnect();
    } catch (error) {
      hostState = classifyNativeError(error);
      status = nativeGuidanceText(hostState);
      updateBadge();
      return null;
    }
    port = p;
    p.onDisconnect.addListener(() => {
      if (port !== p) return;
      port = null;
      const uncertain = unconfirmedSave;
      const neverPaired = !capability;
      clear();
      clearPrivateSessions();
      if (neverPaired) hostState = "exited";
      status = uncertain
        ? "结果未确认，请在金库核实，勿重复保存"
        : neverPaired
          ? "Locklark 原生宿主已退出，请确认桌面端已安装并重新连接"
          : "原生连接已断开，请重新连接";
      if (otpUnknown) status += " · " + OTP_UNKNOWN;
      void api.runtime.lastError;
    });
    p.onMessage.addListener((message) => {
      if (port !== p) {
        if (message && typeof message === "object" && "code" in message)
          message.code = "";
        return;
      }
      if (!core.validResponse(message)) {
        if (message && typeof message === "object" && "code" in message)
          message.code = "";
        disconnectWithStatus("原生协议错误，请重新连接");
        return;
      }
      if (message?.type === "locked") {
        const uncertain = unconfirmedSave;
        clear();
        clearPrivateSessions();
        status = uncertain
          ? "原生金库已锁定 · 结果未确认，请在金库核实，勿重复保存"
          : "原生金库已锁定，请重新连接并配对";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        return;
      }
      if (message.type === "unpaired") {
        const uncertain = unconfirmedSave;
        clear();
        clearPrivateSessions();
        status = uncertain
          ? "结果未确认，请在金库核实，勿重复保存"
          : "扩展连接已到期，请重新连接并配对";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        return;
      }
      if (message.type === "unlocked") {
        // Desktop-shared broker re-unlocked: the host rotated the capability
        // and invalidated every in-flight request, so mirror that locally.
        const uncertain = unconfirmedSave;
        clear();
        clearPrivateSessions();
        capability = message.capability;
        message.capability = "";
        quickFill = message.quick_fill === true;
        hostCapabilities = Array.isArray(message.capabilities)
          ? message.capabilities.slice()
          : [];
        refreshPasskeyConditionalSupport();
        status = uncertain
          ? "桌面已解锁 · 结果未确认，请在金库核实，勿重复保存"
          : "桌面已解锁，已连接，请读取当前网站候选";
        if (otpUnknown) status += " · " + OTP_UNKNOWN;
        updateBadge();
        rebuildContextMenus();
        return;
      }
      if (!message || message.v !== 1 || typeof message.id !== "string")
        return disconnectWithStatus("原生协议错误，请重新连接");
      const call = calls.get(message.id);
      if (!call) {
        if ("code" in message) message.code = "";
        if (retired.delete(message.id)) return;
        return disconnectWithStatus("原生协议错误，请重新连接");
      }
      calls.delete(message.id);
      clearTimeout(call.timer);
      if (message.type === "error") {
        const refusal = Error("refused");
        refusal.knownRefusal = true;
        call.reject(refusal);
        return;
      }
      const expected = {
        hello: "paired",
        match: "candidates",
        fill: "fill",
        cancel: "cancelled",
        "cancel-save": "cancelled",
        "save-new": "save-ready",
        "save-update": "save-ready",
        "commit-ready": "saved",
        "stage-save": "save-staged",
        "pending-save": "save-pending",
        "commit-staged-save": "saved",
        "dismiss-save": "save-dismissed",
        generate: "generated",
        otp: "otp-ready",
        "otp-ack": "otp-fill",
        "cancel-otp": "cancelled",
        "passkey-create": "passkey-result",
        "passkey-get": "passkey-result",
        "passkey-list": "passkey-candidates",
        "passkey-signal": "passkey-signal-accepted",
        "vault-search": "vault-items",
        "vault-list": "vault-items",
        "item-get": "item-detail",
        "item-reveal-field": "field-value",
        "item-copy-field": "field-value",
        "prepare-copy-field": "copy-prepared",
        "commit-copy-field": "copy-result",
        "cancel-copy-field": "copy-cancelled",
        "item-save": "saved",
        "item-state": "saved",
        "unlock-request": "status",
        "item-history": "item-history",
        "item-restore-history": "saved",
        generate: "generated",
        "fill-profile": "profile-fill",
        "match-profiles": "profiles",
        "attachment-begin": "attachment-transfer",
        "attachment-chunk": "attachment-transfer",
        "attachment-commit": "attachment-saved",
        "attachment-cancel": "attachment-cancelled",
        "attachment-read": "attachment-data",
        "attachment-remove": "attachment-removed",
        "passkey-remove": "passkey-removed",
        watchtower: "watchtower",
      }[call.type];
      if (
        message.type === "unknown" &&
        [
          "commit-ready",
          "cancel-save",
          "cancel-otp",
          "passkey-create",
          "passkey-get",
          "passkey-list",
          "passkey-remove",
        ].includes(call.type)
      ) {
        call.resolve(message);
        return;
      }
      const accepted =
        call.type === "fill"
          ? ["fill", "filled", "filled-identity", "filled-card"]
          : {
              "vault-search": ["items", "vault-items"],
              "vault-list": ["items", "vault-items"],
              "item-save": ["item-saved", "saved"],
              "item-state": ["item-saved", "saved"],
              "item-restore-history": ["item-saved", "saved"],
              "fill-profile": ["profile-fill"],
            }[call.type] || [expected];
      if (!accepted.includes(message.type)) {
        if ("code" in message) message.code = "";
        call.reject(Error("refused"));
        disconnectWithStatus("原生协议错误，请重新连接");
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
      quickFill = response.quick_fill === true;
      hostCapabilities = Array.isArray(response.capabilities)
        ? response.capabilities.filter(
            (value) => typeof value === "string" && value.length <= 64,
          )
        : [];
      refreshPasskeyConditionalSupport();
      if (
        hostCapabilities.includes("shared-session-v1") &&
        !hostCapabilities.includes("popup-vault-v1")
      ) {
        hostState = "outdated";
        status = "Locklark 原生宿主版本过旧，请升级桌面端后重新连接";
      } else {
        hostState = "";
        status = "已连接，请读取当前网站候选";
      }
      updateBadge();
      rebuildContextMenus();
    } catch (error) {
      if (error?.timeout) {
        hostState = "timeout";
        status = "等待 Locklark 解锁超时：请在 Locklark 窗口中完成解锁后重试";
        updateBadge();
        return;
      }
      if (port === p && generation === epoch) {
        disconnect();
        status = "连接未获批准或已过期";
      }
    }
  }
  async function match(category = "login", frameId = 0) {
    if (!validCategory(category)) throw Error("refused");
    if (!Number.isSafeInteger(frameId) || frameId < 0) throw Error("refused");
    if (!capability || pending || pendingOTP || pendingPasskey)
      throw Error("refused");
    rows = [];
    context = null;
    matchCategory = category;
    updateBadge();
    const generation = epoch,
      c = await captureTopDocument(frameId);
    await current(c);
    if (generation !== epoch) throw Error("refused");
    const fieldsToSend = fields(c);
    if (category !== "login") fieldsToSend.category = category;
    const response = await request("match", fieldsToSend);
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
      !Array.isArray(next) ||
      next.length > 100 ||
      next.some((r) => !core.validCandidate(r))
    )
      throw Error("refused");
    context = c;
    rows = next.map((row) => ({
      ...row,
      category: row.category || category,
    }));
    status = `${rows.length} 个当前网站${
      category === "login" ? "登录" : category === "identity" ? "身份信息" : "信用卡"
    }`;
    updateBadge();
    rebuildContextMenus();
  }
  async function fill(
    itemId,
    revision,
    category = "login",
    userAuthorized = false,
  ) {
    if (!validCategory(category)) throw Error("refused");
    if (category === "credit_card" && userAuthorized !== true)
      throw Error("refused");
    const row = rows.find(
        (r) =>
          r.id === itemId &&
          r.revision === revision &&
          (category === "login"
            ? rowCategory(r) === "login"
            : rowCategory(r) === category),
      ),
      c = context,
      generation = epoch;
    if (!capability || pending || pendingOTP || pendingPasskey || !row || !c)
      throw Error("refused");
    const intent = {
      itemId,
      revision,
      category,
      tabId: c.tabId,
      windowId: c.windowId,
    };
    pending = intent;
    status =
      category === "login"
        ? quickFill
          ? "正在填充所选账号"
          : "请在原生窗口核对来源、条目与修订并批准"
        : "请在原生窗口批准本次敏感字段填充";
    let response;
    try {
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      const fieldsToSend = { ...fields(c), item_id: itemId, revision };
      if (category !== "login") fieldsToSend.category = category;
      response = await request("fill", fieldsToSend);
      if (generation !== epoch) throw Error("refused");
      await bounded(current(c), generation);
      if (generation !== epoch) throw Error("refused");
      if (category === "identity" || category === "credit_card") {
        const data =
          category === "identity" ? response.identity : response.card;
        if (!data || typeof data !== "object" || Array.isArray(data))
          throw Error("refused");
        await bounded(current(c), generation);
        intent.injectionStarted = true;
        let results;
        try {
          results = await bounded(
            api.scripting.executeScript({
              target: {
                tabId: c.tabId,
                documentIds: [c.documentId],
              },
              func:
                category === "identity"
                  ? core.fillIdentityDocument
                  : core.fillCardDocument,
              args:
                category === "credit_card"
                  ? [
                      c.origin,
                      data,
                      Date.now() + 1500,
                      (c.frameId || 0) > 0,
                      category,
                      true,
                    ]
                  : [
                      c.origin,
                      data,
                      Date.now() + 1500,
                      (c.frameId || 0) > 0,
                      category,
                    ],
            }),
            generation,
          );
        } finally {
          wipeMap(data);
          if (category === "identity") wipeMap(response.identity);
          else wipeMap(response.card);
        }
        if (
          results.length !== 1 ||
          results[0].frameId !== (c.frameId || 0) ||
          results[0].documentId !== c.documentId ||
          results[0].result !== true
        )
          throw Error("refused");
        await bounded(current(c), generation);
        if (generation !== epoch || pending !== intent) throw Error("refused");
        intent.injectionStarted = false;
        fillUnknown = false;
        status =
          category === "identity"
            ? "本次已请求填充身份信息；请核实网站结果"
            : "本次已请求填充信用卡；请核实网站结果";
        return;
      }
      if (
        typeof response.username !== "string" ||
        typeof response.password !== "string" ||
        response.username.length > 16384 ||
        response.password.length > 16384
      )
        throw Error("refused");
      await settingsReady;
      await bounded(current(c), generation);
      const submit = autoLogin && loginOverrides[itemId] !== false;
      // Record the exact credential before injection starts. fillDocument may
      // auto-submit, and its inline-stage-save can arrive while executeScript
      // is still unresolved; remembering only afterwards leaves a false save
      // banner that steals the next Passkey click.
      const previousFill = lastFilledCredentials.get(c.tabId);
      if (previousFill) previousFill.password = "";
      const recorded = {
        origin: c.origin,
        itemId,
        revision,
        username: response.username,
        password: response.password,
        documentId: c.documentId,
        generation,
        filledAt: Date.now(),
        expiresAt: Date.now() + LAST_FILLED_TTL,
      };
      lastFilledCredentials.set(c.tabId, recorded);
      const rollback = () => {
        if (lastFilledCredentials.get(c.tabId) !== recorded) return;
        recorded.password = "";
        lastFilledCredentials.delete(c.tabId);
      };
      intent.injectionStarted = true;
      let results;
      try {
        results = await bounded(
          api.scripting.executeScript({
            target: {
              tabId: c.tabId,
              documentIds: [c.documentId],
            },
            func: core.fillDocument,
            args: [
              c.origin,
              response.username,
              response.password,
              Date.now() + 1500,
              false,
              submit,
              (c.frameId || 0) > 0,
            ],
          }),
          generation,
        );
      } catch (error) {
        rollback();
        throw error;
      }
      const filled = results[0]?.result;
      if (
        results.length !== 1 ||
        results[0].frameId !== (c.frameId || 0) ||
        results[0].documentId !== c.documentId ||
        !(filled === true || (filled && filled.ok === true))
      ) {
        rollback();
        throw Error("refused");
      }
      await bounded(current(c), generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.injectionStarted = false;
      fillUnknown = false;
      const step =
        filled && typeof filled === "object" && typeof filled.step === "string"
          ? filled.step
          : "combined";
      rememberStep(c, itemId, revision, row.title, step);
      status = submit
        ? "已请求填充及登录；请核实网站结果"
        : "本次已请求填充；未自动提交";
    } catch {
      if (generation === epoch && pending === intent) {
        fillUnknown = intent.injectionStarted === true;
        status = fillUnknown ? FILL_UNKNOWN : "本次填充未完成；未自动重试";
      }
    } finally {
      if (response) {
        response.username = "";
        response.password = "";
        wipeMap(response.identity);
        wipeMap(response.card);
      }
      if (generation === epoch && pending === intent) {
        pending = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function clearCapture(results) {
    if (Array.isArray(results))
      for (const row of results) {
        if (row?.result && typeof row.result === "object") {
          row.result.username = "";
          row.result.password = "";
        }
      }
  }
  async function captureValues(c, generation) {
    const promise = api.scripting.executeScript({
      target: { tabId: c.tabId, documentIds: [c.documentId] },
      func: core.fillDocument,
      args: [c.origin, "", "", Date.now() + 1500, true],
    });
    let live = true;
    promise.then(
      (rows) => {
        if (!live || generation !== epoch) clearCapture(rows);
      },
      () => {},
    );
    try {
      const result = await bounded(promise, generation);
      if (
        result.length !== 1 ||
        result[0].frameId !== 0 ||
        result[0].documentId !== c.documentId ||
        !result[0].result ||
        typeof result[0].result !== "object"
      ) {
        clearCapture(result);
        throw Error("refused");
      }
      return result;
    } finally {
      live = false;
    }
  }
  async function verifySaveDocument(c, generation) {
    const active = await bounded(
      api.tabs.query({ active: true, currentWindow: true }),
      generation,
    );
    if (
      active.length !== 1 ||
      active[0].id !== c.tabId ||
      active[0].windowId !== c.windowId ||
      core.originFromURL(active[0].url) !== c.origin
    )
      throw Error("refused");
    const probe = await bounded(
      api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.probe,
      }),
      generation,
    );
    if (
      probe.length !== 1 ||
      probe[0].frameId !== 0 ||
      probe[0].documentId !== c.documentId ||
      !probe[0].result?.top ||
      probe[0].result.origin !== c.origin
    )
      throw Error("refused");
    const final = await bounded(
      api.tabs.query({ active: true, currentWindow: true }),
      generation,
    );
    if (
      final.length !== 1 ||
      final[0].id !== c.tabId ||
      final[0].windowId !== c.windowId ||
      core.originFromURL(final[0].url) !== c.origin
    )
      throw Error("refused");
  }
  async function save(itemId, revision) {
    const generation = epoch,
      previous = context;
    if (
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey ||
      unconfirmedSave
    )
      throw Error("refused");
    if (itemId && !rows.some((r) => r.id === itemId && r.revision === revision))
      throw Error("refused");
    const intent = {
      kind: "save",
      requestId: id(),
      tabId: null,
      windowId: null,
      commitStarted: false,
    };
    pending = intent;
    status = "正在捕获当前登录";
    let captured;
    try {
      const c = await bounded(captureTopDocument(), generation);
      intent.tabId = c.tabId;
      intent.windowId = c.windowId;
      if (itemId && !core.sameContext(c, previous)) throw Error("refused");
      await verifySaveDocument(c, generation);
      captured = await captureValues(c, generation);
      await verifySaveDocument(c, generation);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      const values = captured[0].result;
      if (
        typeof values.username !== "string" ||
        typeof values.password !== "string" ||
        values.password.length === 0 ||
        !values.username.isWellFormed() ||
        !values.password.isWellFormed() ||
        new TextEncoder().encode(values.username).length > 16384 ||
        new TextEncoder().encode(values.password).length > 16384
      )
        throw Error("refused");
      const fieldsToSend = {
        ...fields(c),
        window_id: c.windowId,
        username: values.username,
        password: values.password,
      };
      if (itemId) {
        fieldsToSend.item_id = itemId;
        fieldsToSend.revision = revision;
      }
      const waiting = request(
        itemId ? "save-update" : "save-new",
        fieldsToSend,
        35000,
        intent.requestId,
      );
      clearCapture(captured);
      captured = null;
      status = "请在原生窗口核对并批准保存登录";
      const ready = await waiting;
      if (generation !== epoch || pending !== intent) throw Error("refused");
      status = "已批准，正在核对当前页面";
      await bounded(verifySaveDocument(c, generation), generation, 1500);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.commitStarted = true;
      unconfirmedSave = true;
      status = "正在保存";
      const result = await request(
        "commit-ready",
        { capability, request_id: intent.requestId, nonce: ready.nonce },
        15000,
      );
      if (generation !== epoch || pending !== intent) throw Error("refused");
      if (result.type === "saved") unconfirmedSave = false;
      status =
        result.type === "saved"
          ? "已保存"
          : "结果未确认，请在金库核实，勿重复保存";
    } catch (error) {
      if (generation === epoch && pending === intent) {
        if (error.knownRefusal) unconfirmedSave = false;
        status =
          intent.commitStarted && !error.knownRefusal
            ? "结果未确认，请在金库核实，勿重复保存"
            : "未保存";
        if (capability)
          void request("cancel-save", {
            capability,
            request_id: intent.requestId,
          }).catch(() => {});
      }
    } finally {
      clearCapture(captured);
      if (generation === epoch && pending === intent) {
        pending = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function generatorOptions(params = {}) {
    const mode = ["random", "memorable", "pin"].includes(params.mode)
      ? params.mode
      : "random";
    if (mode === "memorable") {
      const length =
        Number.isSafeInteger(params.length)
          ? params.length
          : params.wordCount ?? generatorDefaults.wordCount;
      return {
        mode,
        length,
        digits: typeof params.digits === "boolean" ? params.digits : false,
        separator:
          typeof params.separator === "string"
            ? params.separator
            : generatorDefaults.separator,
        capitalize:
          typeof params.capitalize === "boolean"
            ? params.capitalize
            : generatorDefaults.capitalize,
      };
    }
    if (mode === "pin")
      return {
        mode,
        length: Number.isSafeInteger(params.length)
          ? params.length
          : params.pinLength ?? generatorDefaults.pinLength,
      };
    return {
      mode,
      length: Number.isSafeInteger(params.length)
        ? params.length
        : generatorDefaults.length,
      digits:
        typeof params.digits === "boolean"
          ? params.digits
          : generatorDefaults.digits,
      symbols:
        typeof params.symbols === "boolean"
          ? params.symbols
          : generatorDefaults.symbols,
    };
  }
  async function generateResult(params) {
    const options = generatorOptions(params);
    if (capability && hostCapabilities.includes("generate-v1")) {
      try {
        const response = await request("generate", {
          capability,
          options: JSON.stringify(options),
        });
        if (
          response.type === "generated" &&
          typeof response.generated_password === "string"
        )
          return {
            password: response.generated_password,
            profile: response.profile,
            historyId: response.history_id || "",
          };
      } catch {}
    }
    return { ...core.generatePassword(options), historyId: "" };
  }
  function recordGenerated(origin, username, generated) {
    const createdAt = Date.now();
    const entry = {
      id: id(),
      origin,
      username: typeof username === "string" ? username : "",
      password: generated.password,
      profile: generated.profile,
      createdAt,
      expiresAt: createdAt + GENERATED_TTL,
    };
    generatedHistory.unshift(entry);
    while (generatedHistory.length > HISTORY_LIMIT) {
      const removed = generatedHistory.pop();
      if (removed) removed.password = "";
    }
    scheduleGeneratedPrune();
    return entry.id;
  }
  function generatedHistoryView() {
    pruneGenerated();
    return generatedHistory.map((entry) => ({
      id: entry.id,
      origin: entry.origin,
      username: entry.username,
      password: entry.password,
      profile: entry.profile,
      createdAt: entry.createdAt,
    }));
  }
  function addNeverOrigin(origin) {
    if (neverSaveOrigins.includes(origin)) return;
    if (neverSaveOrigins.length >= 256) neverSaveOrigins.shift();
    neverSaveOrigins.push(origin);
  }
  async function persistNeverOrigins() {
    try {
      await api.storage.local.set({ neverSaveOrigins: [...neverSaveOrigins] });
    } catch {}
  }
  async function stageSave(values, c) {
    pruneStaged();
    if (!validCredentialText(values?.password)) return { mode: "never" };
    const username =
      typeof values.username === "string" ? values.username.slice(0, 16384) : "";
    if (!validCredentialText(username, true)) return { mode: "never" };
    if (!offerSaveLogins || neverSaveOrigins.includes(c.origin))
      return { mode: "never" };
    const last = lastFilledCredentials.get(c.tabId);
    if (
      last &&
      Date.now() < last.expiresAt &&
      last.origin === c.origin &&
      last.documentId === c.documentId &&
      last.generation === epoch &&
      last.username === username &&
      last.password === values.password &&
      values.isPasswordChange !== true
    )
      return { mode: "unchanged" };
    // Only one pending save is kept per tab and origin. A new submission replaces
    // the previous proposal instead of leaking the older password for five minutes.
    for (const [stageId, record] of stagedSaves)
      if (record.tabId === c.tabId && record.origin === c.origin)
        removeStaged(stageId);
    let mode = values.isPasswordChange === true ? "update" : "new";
    let matched = null;
    if (capability) {
      if (
        (!context || context.origin !== c.origin || !rows.length) &&
        !pending &&
        !pendingOTP &&
        !pendingPasskey
      ) {
        try {
          await match();
        } catch {}
      }
      if (values.isPasswordChange === true && rows.length >= 1)
        matched = rows[0];
      else if (
        username &&
        rows.find(
          (row) =>
            row.title &&
            row.title.toLowerCase() === username.toLowerCase(),
        )
      )
        matched =
          rows.find(
            (row) =>
              row.title &&
              row.title.toLowerCase() === username.toLowerCase(),
          ) || null;
      else if (
        typeof values.itemId === "string" &&
        rows.some(
          (row) =>
            row.id === values.itemId && row.revision === values.revision,
        )
      )
        matched =
          rows.find((row) => row.id === values.itemId) || null;
      if (matched) mode = "update";
    }
    const title =
      typeof values.title === "string" && values.title.trim()
        ? values.title.trim().slice(0, 1024)
        : new URL(c.origin).hostname;
    const record = {
      stageId: id(),
      tabId: c.tabId,
      windowId: c.windowId,
      origin: c.origin,
      username,
      password: values.password,
      title,
      isNewPassword: values.isNewPassword === true,
      isPasswordChange: values.isPasswordChange === true,
      mode,
      existingItemId: matched?.id || "",
      existingRevision: matched?.revision || "",
      createdAt: Date.now(),
      expiresAt: Date.now() + STAGED_TTL,
      native: false,
      timer: null,
    };
    if (capability && hostCapabilities.includes("stage-save-v1")) {
      try {
        const response = await request("stage-save", {
          capability,
          origin: c.origin,
          tab_id: c.tabId,
          document_id: c.documentId,
          window_id: c.windowId,
          username,
          password: values.password,
          mode,
          title,
          item_id: record.existingItemId,
          revision: record.existingRevision,
        });
        const staged = response.staged_save;
        if (staged) {
          record.stageId = staged.stage_id;
          record.origin = staged.origin;
          record.username = staged.username;
          record.title = staged.title;
          record.mode = staged.mode;
          record.existingItemId = staged.existing_item_id || "";
          record.existingRevision = staged.existing_revision || "";
          if (Number.isSafeInteger(staged.expires_at))
            record.expiresAt = Math.min(record.expiresAt, staged.expires_at);
          record.native = true;
        }
      } catch {
        record.native = false;
      }
    }
    if (record.mode === "unchanged" || record.mode === "never")
      return { mode: record.mode };
    stagedSaves.set(record.stageId, record);
    armStagedTimer(record);
    return { mode: record.mode, stageId: record.stageId };
  }
  async function commitStagedSave(stageId, options, c) {
    pruneStaged();
    const record = stagedSaves.get(stageId);
    if (
      !record ||
      record.origin !== c.origin ||
      !(Date.now() < record.expiresAt) ||
      record.committing
    )
      throw Error("refused");
    record.committing = true;
    // connect() advances the epoch, so only capture the generation after a
    // possible lazy connection. The staged record itself survives the clear.
    if (!capability) await connect();
    const generation = epoch;
    try {
      await settingsReady;
      if (!capability || generation !== epoch) throw Error("refused");
      await current(c);
      let mode = ["new", "update"].includes(options?.mode)
        ? options.mode
        : record.mode;
      let itemId =
        typeof options?.itemId === "string"
          ? options.itemId
          : record.existingItemId;
      let revision =
        typeof options?.revision === "string"
          ? options.revision
          : record.existingRevision;
      if (!context || context.origin !== c.origin || !rows.length) {
        try {
          await match();
        } catch {}
      }
      if (mode === "update") {
        const matchRow = () =>
          rows.find((row) => row.id === itemId) ||
          rows.find((row) => row.title === record.title) ||
          (rows.length === 1 ? rows[0] : null);
        if (!itemId || !revision || !rows.some((row) => row.id === itemId)) {
          const found = matchRow();
          if (found) {
            itemId = found.id;
            revision = found.revision;
          } else mode = "new";
        }
      }
      if (mode === "update" && (!itemId || !revision)) mode = "new";
      const title =
        typeof options?.title === "string" && options.title.trim()
          ? options.title.trim().slice(0, 1024)
          : record.title;
      let result;
      if (hostCapabilities.includes("stage-save-v1")) {
        result = await request("commit-staged-save", {
          capability,
          stage_id: stageId,
          origin: c.origin,
          tab_id: c.tabId,
          document_id: c.documentId,
          window_id: c.windowId,
          title,
          mode,
          item_id: mode === "update" ? itemId : "",
          revision: mode === "update" ? revision : "",
        });
        if (result.type !== "saved") throw Error("refused");
      } else {
        await verifySaveDocument(c, generation);
        const fieldsToSend = {
          ...fields(c),
          window_id: c.windowId,
          username: record.username,
          password: record.password,
        };
        if (mode === "update") {
          fieldsToSend.item_id = itemId;
          fieldsToSend.revision = revision;
        } else {
          // A v1 save-update must not carry a title (the native host binds it to
          // the existing row); save-new may use the user-edited title.
          fieldsToSend.title = title;
        }
        const ready = await request(
          mode === "update" ? "save-update" : "save-new",
          fieldsToSend,
          35000,
        );
        if (ready.type !== "save-ready") throw Error("refused");
        await verifySaveDocument(c, generation);
        if (generation !== epoch) throw Error("refused");
        record.commitStarted = true;
        unconfirmedSave = true;
        result = await request("commit-ready", {
          capability,
          request_id: ready.id,
          nonce: ready.nonce,
        });
        if (result.type === "saved") unconfirmedSave = false;
        if (result.type !== "saved") throw Error("refused");
      }
      removeStaged(stageId);
      status = "已保存";
      notify("已保存登录", title);
      return { saved: true, mode, title, status };
    } catch (error) {
      if (!record.commitStarted || !unconfirmedSave) status = "未保存";
      throw error;
    } finally {
      record.committing = false;
    }
  }
  async function dismissStaged(stageId, neverForOrigin, c, originOverride) {
    pruneStaged();
    const record = stageId ? stagedSaves.get(stageId) : null;
    const origin = record?.origin || originOverride || c?.origin || "";
    if (neverForOrigin) {
      try {
        if (core.originFromURL(origin) === origin) {
          addNeverOrigin(origin);
          await persistNeverOrigins();
        }
      } catch {}
    }
    if (
      record &&
      capability &&
      hostCapabilities.includes("stage-save-v1") &&
      record.native
    ) {
      try {
        const response = await request("dismiss-save", {
          capability,
          stage_id: record.stageId,
          never_for_origin: neverForOrigin === true,
        });
        if (Array.isArray(response.never_origins))
          neverSaveOrigins = sanitizeOrigins(response.never_origins);
      } catch {}
    }
    if (record) removeStaged(record.stageId);
    return {
      dismissed: true,
      neverSaveOrigins: [...neverSaveOrigins],
      pendingSave: serializeStaged(stagedForTab(c?.tabId, c?.origin)),
    };
  }
  async function inlineGenerateFill(params, c, generation) {
    const suppliedPassword =
      typeof params?.password === "string" &&
      params.password.length >= 4 &&
      params.password.length <= 256 &&
      params.password.isWellFormed()
        ? params.password
        : "";
    let generated;
    if (suppliedPassword) {
      let profile = null;
      if (
        params.profile &&
        typeof params.profile === "object" &&
        !Array.isArray(params.profile) &&
        ["random", "memorable", "pin"].includes(params.profile.mode) &&
        Number.isSafeInteger(params.profile.length) &&
        params.profile.length >= 1 &&
        params.profile.length <= 256 &&
        Number.isSafeInteger(params.profile.alphabet_size) &&
        params.profile.alphabet_size >= 2 &&
        params.profile.alphabet_size <= 1000000 &&
        Number.isSafeInteger(params.profile.entropy_bits_floor) &&
        params.profile.entropy_bits_floor >= 0
      )
        profile = {
          mode: params.profile.mode,
          length: params.profile.length,
          alphabet_size: params.profile.alphabet_size,
          entropy_bits_floor: params.profile.entropy_bits_floor,
        };
      if (!profile)
        profile = core.generatePassword(generatorOptions(params)).profile;
      generated = {
        password: suppliedPassword,
        profile,
        historyId: "",
      };
    } else generated = await generateResult(params);
    const historyId = recordGenerated(
      c.origin,
      typeof params.username === "string" ? params.username : "",
      generated,
    );
    let fill = null;
    try {
      const results = await api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.fillGeneratedPassword,
        args: [c.origin, generated.password, Date.now() + 1500],
      });
      if (
        generation === epoch &&
        results.length === 1 &&
        results[0].frameId === 0 &&
        results[0].documentId === c.documentId &&
        results[0].result?.ok === true
      )
        fill = results[0].result;
    } catch {}
    const staged = await stageSave(
      {
        username: fill?.username || params.username || "",
        password: generated.password,
        isNewPassword: true,
        isPasswordChange: fill?.isPasswordChange === true,
      },
      c,
    );
    return {
      password: generated.password,
      profile: generated.profile,
      historyId,
      filledCount: fill?.filledCount || 0,
      stageId: staged.stageId || "",
      mode: staged.mode || "",
    };
  }
  async function activeTabInfo() {
    try {
      const tabs = await api.tabs.query({ active: true, currentWindow: true });
      if (tabs.length !== 1) return null;
      const tab = tabs[0];
      if (!Number.isSafeInteger(tab.id) || !Number.isSafeInteger(tab.windowId))
        return null;
      return {
        tabId: tab.id,
        windowId: tab.windowId,
        origin: core.originFromURL(tab.url),
      };
    } catch {
      return null;
    }
  }
  async function activePendingSave() {
    const info = await activeTabInfo();
    return info ? serializeStaged(stagedForTab(info.tabId, info.origin)) : null;
  }
  function statePayload(extra = {}) {
    return {
      connected: !!capability,
      autoLogin,
      quickFill,
      loginOverrides,
      offerSavePasskeys,
      offerUsePasskeys,
      offerSaveLogins,
      neverSaveOrigins: [...neverSaveOrigins],
      generatorDefaults: { ...generatorDefaults },
      generatedHistory: generatedHistoryView(),
      watchtowerHIBP,
      watchtower: watchtowerReport,
      status:
        status +
        (otpUnknown && !status.includes(OTP_UNKNOWN)
          ? " · " + OTP_UNKNOWN
          : "") +
        (fillUnknown && !status.includes(FILL_UNKNOWN)
          ? " · " + FILL_UNKNOWN
          : "") +
        (passkeyUnknown && !status.includes(PASSKEY_UNKNOWN)
          ? " · " + PASSKEY_UNKNOWN
          : ""),
      candidates: rows.map(candidateView),
      preferredItemId: multiStepFor(context?.tabId, context?.origin)?.itemId || "",
      preferredTitle: multiStepFor(context?.tabId, context?.origin)?.title || "",
      step: multiStepFor(context?.tabId, context?.origin)?.stepCompleted || "",
      pending: !!pending || !!pendingOTP || !!pendingPasskey,
      otpPending: !!pendingOTP,
      saveBlocked: unconfirmedSave,
      origin: context?.origin || "",
      ...extra,
    };
  }

  function validOTPProbe(value, c) {
    return (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).sort().join(",") ===
        "now,origin,timeOrigin,top,wall" &&
      value.top === ((c.frameId || 0) === 0) &&
      value.origin === c.origin &&
      Number.isFinite(value.timeOrigin) &&
      value.timeOrigin > 0 &&
      Number.isFinite(value.now) &&
      value.now >= 0 &&
      Number.isSafeInteger(value.wall) &&
      value.wall > 0
    );
  }
  async function otpProbe(c, generation, remaining = () => 1500) {
    await bounded(current(c), generation, remaining());
    const results = await bounded(
      api.scripting.executeScript({
        target: {
          tabId: c.tabId,
          documentIds: [c.documentId],
        },
        func: core.otpDocument,
        args: [c.origin, "probe", null, null, (c.frameId || 0) > 0],
      }),
      generation,
      remaining(),
    );
    if (
      results.length !== 1 ||
      results[0].frameId !== (c.frameId || 0) ||
      results[0].documentId !== c.documentId ||
      !validOTPProbe(results[0].result, c)
    )
      throw Error("refused");
    await bounded(current(c), generation, remaining());
    return results[0].result;
  }
  function cancelOTP() {
    const intent = pendingOTP;
    if (!intent) return;
    pendingOTP = null;
    context = null;
    rows = [];
    advanceEpoch();
    const cancelStatus = intent.sent ? OTP_UNKNOWN : "本次验证码填充已取消";
    const cancellation = { generation: epoch, status: cancelStatus };
    otpCancellation = cancellation;
    otpUnknown = intent.sent;
    status = cancelStatus;
    const ownsCancellationView = () =>
      !pending && !pendingOTP && !context && status === cancellation.status;
    updateBadge();
    rebuildContextMenus();
    if (!intent.sent || !capability) return;
    // Host cancellation cannot retract an injection already submitted to the
    // browser, even if its executeScript promise has not settled yet.
    void request("cancel-otp", {
      capability,
      request_id: intent.requestId,
    }).then(
      (result) => {
        if (
          otpCancellation !== cancellation ||
          epoch !== cancellation.generation
        )
          return;
        const confirmed =
          result.type === "cancelled" && !intent.injectionStarted;
        otpUnknown = !confirmed;
        // A later ordinary fill/save/match owns its own status. The C result
        // still resolves the historical OTP uncertainty without replacing it.
        if (ownsCancellationView())
          status = confirmed ? "本次验证码填充已取消" : OTP_UNKNOWN;
      },
      () => {
        if (
          otpCancellation === cancellation &&
          epoch === cancellation.generation
        ) {
          otpUnknown = true;
          if (ownsCancellationView()) status = OTP_UNKNOWN;
        }
      },
    );
  }
  async function otp(itemId, revision) {
    const row = rows.find((r) => r.id === itemId && r.revision === revision);
    if (
      !row ||
      !context ||
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    const c = context,
      generation = epoch;
    const intent = {
      requestId: id(),
      tabId: c.tabId,
      windowId: c.windowId,
      sent: false,
      ackSent: false,
      injectionStarted: false,
    };
    otpCancellation = null;
    otpUnknown = false;
    pendingOTP = intent;
    status = "请在原生窗口批准本次验证码填充";
    let response = null,
      live = true;
    try {
      await otpProbe(c, generation);
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      intent.sent = true;
      const challenge = await request(
        "otp",
        {
          ...fields(c),
          window_id: c.windowId,
          item_id: itemId,
          revision,
        },
        35000,
        intent.requestId,
      );
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      // This single background deadline starts BEFORE the final probe. The page
      // carries its own clock sample; clocks from different worlds never mix.
      const started = performance.now(),
        wall = Date.now();
      const remaining = () => {
        const now = performance.now(),
          elapsed = now - started,
          wallNow = Date.now();
        if (
          !Number.isFinite(elapsed) ||
          elapsed < 0 ||
          elapsed >= 1500 ||
          wallNow < wall ||
          wallNow >= wall + 1500
        )
          throw Error("refused");
        return Math.max(1, Math.min(1500 - elapsed, wall + 1500 - wallNow));
      };
      const timing = await otpProbe(c, generation, remaining);
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      const ackTimeout = remaining();
      intent.ackSent = true;
      const reply = request(
        "otp-ack",
        {
          capability,
          request_id: intent.requestId,
          nonce: challenge.nonce,
        },
        ackTimeout,
      );
      challenge.nonce = "";
      // A response which arrives after navigation/timeout is never retained.
      reply.then(
        (value) => {
          if (!live || generation !== epoch || pendingOTP !== intent)
            value.code = "";
        },
        (error) => {
          intent.knownRefusal = error.knownRefusal === true;
        },
      );
      response = await bounded(reply, generation, remaining());
      if (generation !== epoch || pendingOTP !== intent) throw Error("refused");
      await bounded(current(c), generation, remaining());
      const args = [
        c.origin,
        "fill",
        response.code,
        timing,
        (c.frameId || 0) > 0,
      ];
      response.code = "";
      let injection;
      try {
        remaining();
        intent.injectionStarted = true;
        injection = api.scripting.executeScript({
          target: {
            tabId: c.tabId,
            documentIds: [c.documentId],
          },
          func: core.otpDocument,
          args,
        });
      } finally {
        args[2] = "";
      }
      const results = await bounded(injection, generation, remaining());
      remaining();
      if (
        generation !== epoch ||
        pendingOTP !== intent ||
        results.length !== 1 ||
        results[0].frameId !== (c.frameId || 0) ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      multiStepSessions.delete(c.tabId);
      status = "本次已请求填充验证码；未自动提交";
    } catch {
      if (generation === epoch && pendingOTP === intent) {
        otpUnknown =
          intent.injectionStarted || (intent.ackSent && !intent.knownRefusal);
        status = otpUnknown ? OTP_UNKNOWN : "本次验证码填充被拒绝或已过期";
        if (capability)
          void request("cancel-otp", {
            capability,
            request_id: intent.requestId,
          }).catch(() => {});
      }
    } finally {
      live = false;
      if (response) response.code = "";
      if (generation === epoch && pendingOTP === intent) {
        pendingOTP = null;
        rows = [];
        context = null;
      }
      updateBadge();
      rebuildContextMenus();
    }
  }
  function cancelContext() {
    clearConditionalIntentsWithNotify();
    if (pendingPasskey) {
      if (pendingPasskey.create) passkeyUnknown = true;
      pendingPasskey = null;
      advanceEpoch();
      rows = [];
      context = null;
      if (capability) void request("cancel", { capability }).catch(() => {});
      updateBadge();
      rebuildContextMenus();
      return;
    }
    if (pending?.injectionStarted) fillUnknown = true;
    if (pendingOTP) {
      cancelOTP();
      return;
    }
    if (!context && !pending) {
      updateBadge();
      rebuildContextMenus();
      return;
    }
    const intent = pending;
    context = null;
    rows = [];
    pending = null;
    advanceEpoch();
    status = unconfirmedSave
      ? "结果未确认，请在金库核实，勿重复保存"
      : "页面或活动标签已变化，请重新读取候选";
    if (capability)
      void request(
        intent?.kind === "save" ? "cancel-save" : "cancel",
        intent?.kind === "save"
          ? { capability, request_id: intent.requestId }
          : { capability },
      ).catch(() => {});
    updateBadge();
    rebuildContextMenus();
  }
  // Route lifecycle diagnostic (temporary). One hardcoded event label per
  // branch, so an acceptance run can tell which admission/anchor branch was
  // reached without any URL, token, tab/window/frame id, user data, secret,
  // native payload or exception text. Branches and return values are
  // unchanged: every call site keeps its own if/return structure.
  const ROUTE_LIFECYCLE_DIAG_PREFIX = "[locklark-route-lifecycle] ";
  const ROUTE_LIFECYCLE_DIAG_EVENTS = new Set([
    "activation-startup", "activation-late", "activation-switch",
    "boot-bind-browser-tab-missing", "boot-bind-page-mismatch",
    "boot-bind-no-unique-boot", "boot-bind-wrong-window",
    "boot-bind-inactive-tab", "boot-bind-bound",
    "fallback-no-grant", "fallback-not-live", "fallback-wrong-tab",
    "fallback-anchor-mismatch", "fallback-accepted",
    "port-admit-started", "port-admit-early", "port-admit-fallback",
    "port-sender-mismatch", "port-invalid-grant-or-tab",
    "port-anchor-mismatch", "port-ready-sent",
    "port-disconnected", "port-refused",
    "activation-target-confirmed", "activation-target-missing",
    "activation-target-mismatch", "route-tab-url-mismatch",
    "source-loading", "source-url-mismatch", "route-tab-removed",
    "source-tab-removed", "route-create-failed", "route-create-invalid-tab",
    "route-create-not-owned", "route-create-tab-mismatch",
    "route-expired", "routes-revoked-all",
  ]);
  const ROUTE_LIFECYCLE_DIAG_LEAVES = ["activation-startup", "activation-late"];
  function routeLifecycleDiag(event) {
    if (!ROUTE_LIFECYCLE_DIAG_EVENTS.has(event)) return;
    try {
      console.info(ROUTE_LIFECYCLE_DIAG_PREFIX + event);
    } catch {}
  }
  // A route survives only while its tab stays the active tab of its window.
  // The one exception is the route's own startup: the browser activates the
  // tab it just opened before tabs.create() resolves, and that activation must
  // neither cancel the captured source context nor advance its epoch. Any
  // later tab change revokes the route; an ordinary switch still cancels.
  function bindRouteTab(grant, tabId, windowId) {
    grant.tabId = tabId;
    if (Number.isSafeInteger(windowId)) grant.windowId = windowId;
    routeBoots.delete(grant);
    routeTabs.set(tabId, grant);
  }
  // Route lifecycle diagnostic only: the leaf branch routeActivation() took,
  // already as its final activation label so no other literal is emitted.
  let routeActivationLeaf = null;
  // Returns "startup" for the route's own first activation and "switch" for
  // anything else (including a later re-activation of an already open route).
  function routeActivation(tabId, windowId) {
    for (const grant of new Set([...routeGrants.values(), ...routeTabs.values()])) {
      if (grant.tabId !== tabId) continue;
      if (grant.startupActivation === true) {
        if (activationInside) routeActivationLeaf = "activation-late";
        revokeRoute(grant);
        return "switch";
      }
      grant.startupActivation = true;
      grant.activated = true;
      return "startup";
    }
    // The grant may not know its tab id yet: the activation can arrive before
    // tabs.create() resolves. Adopt it, then confirm the tab really is the
    // route page; a mismatch fails closed as an ordinary switch.
    const boot = [...routeBoots].find(
      (grant) => !Number.isSafeInteger(windowId) || grant.windowId === windowId,
    );
    if (!boot) return "switch";
    if (activationInside) routeActivationLeaf = "activation-startup";
    bindRouteTab(boot, tabId, windowId);
    boot.startupActivation = true;
    boot.activated = true;
    boot.initialLoad = {};
    routeTabAt(tabId, boot.routeURL).then((tab) => {
      if (routeTabs.get(tabId) !== boot) return;
      if (tab && tab.windowId === boot.windowId) {
        routeLifecycleDiag("activation-target-confirmed");
        return;
      }
      routeLifecycleDiag(tab ? "activation-target-mismatch" : "activation-target-missing");
      revokeRoute(boot);
      cancelContext();
    }, () => {});
    return "startup";
  }
  // Route lifecycle diagnostic only: `routeActivationLeaf` is only recorded
  // while onActivated is inside this function (see `activationInside`), so a
  // later unrelated call cannot overwrite the activation event's own leaf.
  let activationKind = "activation-switch";
  let activationInside = false;
  function routeActivationForActivationEvent(tabId, windowId) {
    activationInside = true;
    try {
      return routeActivation(tabId, windowId);
    } finally {
      activationInside = false;
    }
  }
  api.tabs.onActivated.addListener((info) => {
    activationKind = "activation-switch";
    routeActivationLeaf = null;
    const kind = Number.isSafeInteger(info?.tabId)
      ? routeActivationForActivationEvent(info.tabId, info.windowId)
      : "switch";
    for (const grant of new Set([...routeGrants.values(), ...routeTabs.values()])) {
      // Only the tab that was just activated may keep a route; every other
      // grant is no longer the active tab and ends now.
      if (kind === "startup" && grant.tabId === info.tabId) continue;
      revokeRoute(grant);
    }
    if (kind !== "startup") cancelContext();
    clearCheckoutPicker();
    updateBadge();
    rebuildContextMenus();
    // Fixed kind first (startup vs switch), then the explicit late leaf.
    activationKind = kind === "startup" ? "activation-startup" : "activation-switch";
    if (
      activationKind === "activation-switch" &&
      ROUTE_LIFECYCLE_DIAG_LEAVES.includes(routeActivationLeaf)
    )
      activationKind = routeActivationLeaf;
    routeLifecycleDiag(activationKind);
  });
  // Only the route tab's initial loading of its own exact URL is accepted;
  // any other URL change on it is a navigation and revokes. The source page
  // is not scripted or closed here, only checked: leaving its origin revokes.
  function routeTabUpdated(tabId, change) {
    let grant = routeTabs.get(tabId);
    if (!grant && "url" in change) {
      // Initial load can be reported before tabs.create() resolves.
      const boot = [...routeBoots].find(
        (candidate) => candidate.routeURL && candidate.routeURL === change.url,
      );
      if (boot) {
        // Do not set startupActivation here: onActivated may still follow, and
        // that event is what consumes the one permitted startup activation.
        bindRouteTab(boot, tabId);
        boot.initialLoad = {};
        grant = boot;
      }
    }
    if (!grant) return;
    if ("url" in change && change.url !== grant.routeURL) {
      if (routeTabUpdateInside) routeTabUpdateLabel = "route-tab-url-mismatch";
      revokeRoute(grant);
      return;
    }
    if (change.status === "complete" && grant.initialLoad) {
      grant.initialLoad = null;
    }
  }
  // A route dies with its exact source page: any URL change (same origin
  // included) and any new load of the source tab (a reload or document
  // replacement keeps the URL) revoke it. Only events for the captured tab
  // matter; the source never has to stay active.
  function routeSourceUpdated(tabId, change) {
    const hasURL = "url" in change && change.url !== undefined;
    if (!hasURL && change.status !== "loading") return;
    for (const grant of new Set([...routeGrants.values(), ...routeTabs.values()])) {
      if (grant.source.tabId !== tabId) continue;
      if (change.status === "loading" || (hasURL && change.url !== grant.source.url)) {
        revokeRoute(grant);
      }
    }
  }
  // Route lifecycle diagnostic only: the branch routeTabUpdated() took for
  // this update event, recorded only while the listener is calling it.
  let routeTabUpdateInside = false;
  let routeTabUpdateLabel = null;
  function routeTabUpdatedForUpdateEvent(tabId, change) {
    routeTabUpdateInside = true;
    try {
      return routeTabUpdated(tabId, change);
    } finally {
      routeTabUpdateInside = false;
    }
  }
  api.tabs.onUpdated.addListener((tabId, change) => {
    const sourceRoutes = new Set([...routeGrants.values(), ...routeTabs.values()].filter((grant) => grant.source.tabId === tabId));
    routeTabUpdateLabel = null;
    routeTabUpdatedForUpdateEvent(tabId, change || {});
    routeSourceUpdated(tabId, change || {});
    // Route lifecycle diagnostic only, read after the handler: the source
    // branch routeSourceUpdated() took for these exact grants, if any.
    const event = change || {};
    const hasSourceURL = "url" in event && event.url !== undefined;
    const sourceLoading = event.status === "loading";
    if (
      sourceRoutes.size &&
      (hasSourceURL || sourceLoading) &&
      [...sourceRoutes].some((grant) =>
        sourceLoading || (hasSourceURL && event.url !== grant.source.url),
      )
    )
      routeLifecycleDiag(sourceLoading ? "source-loading" : "source-url-mismatch");
    if (routeTabUpdateLabel) routeLifecycleDiag(routeTabUpdateLabel);
    const session = multiStepSessions.get(tabId);
    if (session && "url" in change) {
      try {
        const origin = core.originFromURL(change.url);
        if (core.siteKey(origin) !== session.siteKey)
          multiStepSessions.delete(tabId);
      } catch {
        multiStepSessions.delete(tabId);
      }
    }
    if ("url" in change || change.status === "loading") {
      clearConditionalIntentsForTab(tabId);
      if (checkoutPicker?.tabId === tabId) clearCheckoutPicker();
    }
    if (
      (context?.tabId === tabId ||
        pending?.tabId === tabId ||
        pendingOTP?.tabId === tabId ||
        pendingPasskey?.tabId === tabId) &&
      ("url" in change || change.status === "loading")
    )
      cancelContext();
    if ("url" in change || change.status === "complete") {
      updateBadge();
      rebuildContextMenus();
    }
    void processOpenAndFill(tabId, change);
  });
  api.tabs.onRemoved?.addListener((tabId) => {
    for (const boot of [...routeBoots]) if (boot.tabId === tabId) {
      routeLifecycleDiag("route-tab-removed");
      revokeRoute(boot);
    }
    if (routeTabs.has(tabId)) {
      routeLifecycleDiag("route-tab-removed");
      revokeRoute(routeTabs.get(tabId));
    }
    for (const grant of [...routeGrants.values()])
      if (grant.source.tabId === tabId) {
        routeLifecycleDiag("source-tab-removed");
        revokeRoute(grant);
      }
    if (checkoutPicker?.tabId === tabId) clearCheckoutPicker();
    multiStepSessions.delete(tabId);
    clearConditionalIntentsForTab(tabId);
    if (
      context?.tabId === tabId ||
      pending?.tabId === tabId ||
      pendingOTP?.tabId === tabId ||
      pendingPasskey?.tabId === tabId
    )
      cancelContext();
  });
  api.windows.onFocusChanged.addListener((windowId) => {
    updateBadge();
    if (windowId === api.windows.WINDOW_ID_NONE) return;
    if (checkoutPicker && checkoutPicker.windowId !== windowId)
      clearCheckoutPicker();
    const bound =
      pendingPasskey?.windowId ??
      pendingOTP?.windowId ??
      pending?.windowId ??
      context?.windowId;
    if (
      (pendingPasskey || pendingOTP || pending || context) &&
      (bound == null || bound !== windowId)
    )
      cancelContext();
  });
  function lockVault() {
    const p = port,
      cap = capability;
    if (p && cap) {
      try {
        p.postMessage({ v: 1, id: id(), type: "lock", capability: cap });
      } catch {}
    }
    disconnectWithStatus("已锁定 Locklark");
    updateBadge();
    rebuildContextMenus();
  }
  async function diagnosticsSnapshot() {
    const manifest = api.runtime.getManifest?.() || {};
    let permissions = [];
    try {
      const granted = await api.permissions?.getAll?.();
      permissions = Array.isArray(granted?.permissions)
        ? granted.permissions.filter((name) => typeof name === "string").sort()
        : [];
    } catch {}
    return {
      extension: {
        version: String(manifest.version || ""),
        manifest_version: manifest.manifest_version || 3,
      },
      connection: {
        connected: !!capability,
        quick_fill: quickFill,
        capabilities: hostCapabilities.slice(),
        state: hostState,
        status,
      },
      counts: {
        candidates: rows.length,
        vault_items: vaultItems.length,
        pending_save: pending ? 1 : 0,
        pending_otp: pendingOTP ? 1 : 0,
        pending_passkey: pendingPasskey ? 1 : 0,
      },
      settings: {
        auto_login: settings.autoLogin === true,
        show_inline_menu: settings.showInlineMenu !== false,
        offer_passkeys: settings.offerPasskeys !== false,
        paste_protection: settings.pasteProtection !== false,
        otp_capture: settings.otpCapture !== false,
        idle_lock_minutes: settings.idleLockMinutes || 0,
        notifications: settings.notifications === true,
      },
      permissions,
      generated_at: new Date().toISOString(),
    };
  }
  async function setSiteSettings(disabledInline, neverSave) {
    if (!context?.origin) throw Error("refused");
    const origin = context.origin;
    const next = core.normalizeSettings({
      ...settings,
      disabledInlineMenuOrigins:
        typeof disabledInline === "boolean"
          ? disabledInline
            ? [...settings.disabledInlineMenuOrigins, origin]
            : settings.disabledInlineMenuOrigins.filter(
                (value) => value !== origin,
              )
          : settings.disabledInlineMenuOrigins,
      neverSaveOrigins:
        typeof neverSave === "boolean"
          ? neverSave
            ? [...settings.neverSaveOrigins, origin]
            : settings.neverSaveOrigins.filter((value) => value !== origin)
          : settings.neverSaveOrigins,
    });
    await api.storage.local.set({
      disabledInlineMenuOrigins: next.disabledInlineMenuOrigins,
      neverSaveOrigins: next.neverSaveOrigins,
    });
    settings = next;
    status = "网站设置已更新";
    updateBadge();
    rebuildContextMenus();
  }
  async function toggleSiteInline() {
    if (!context?.origin) {
      status = "请先读取当前网站候选";
      return;
    }
    try {
      await setSiteSettings(!currentSiteFlags().disabledInline, undefined);
    } catch {
      status = "网站设置未保存";
    }
  }
  async function autofillActiveTab() {
    if (!capability) {
      status = "请先解锁 Locklark";
      updateBadge();
      return;
    }
    try {
      await match();
      if (rows.length === 0) {
        status = "当前网站无匹配登录";
      } else if (rows.length === 1) {
        await fill(rows[0].id, rows[0].revision);
      } else {
        const tabs = await api.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (tabs.length === 1 && Number.isSafeInteger(tabs[0].id))
          await api.tabs
            .sendMessage?.(tabs[0].id, {
              type: "locklark:open-inline-menu",
            })
            .catch(() => {});
        status = `发现 ${rows.length} 个匹配登录，请在页面中选择`;
      }
    } catch {
      status = "自动填充未完成；请确认原生连接和当前 HTTPS 页面";
    }
    updateBadge();
    rebuildContextMenus();
  }
  async function generatePasswordValue(rawOptions) {
    const options = core.normalizeGeneratorDefaults(rawOptions);
    if (capability) {
      try {
        const response = await request(
          "generate",
          { capability, options: JSON.stringify(options) },
          12000,
        );
        return response.password;
      } catch {}
    }
    return core.generatePasswordString(options);
  }
  async function generateAndFill() {
    if (!capability) {
      status = "请先解锁 Locklark";
      updateBadge();
      return;
    }
    let password = "";
    try {
      const options = settings.generatorDefaults;
      try {
        const response = await request(
          "generate",
          { capability, options: JSON.stringify(options) },
          12000,
        );
        password = response.password;
      } catch {
        password = core.generatePasswordString(options);
      }
      const c = await captureTopDocument();
      await current(c);
      const results = await api.scripting.executeScript({
        target: { tabId: c.tabId, documentIds: [c.documentId] },
        func: core.fillGeneratedPasswordDocument,
        args: [c.origin, password, Date.now() + 1500],
      });
      if (
        results.length !== 1 ||
        results[0].frameId !== 0 ||
        results[0].documentId !== c.documentId ||
        results[0].result !== true
      )
        throw Error("refused");
      status = "已生成并填充新密码";
    } catch {
      status = "生成密码未完成；请确认当前密码输入框";
    } finally {
      password = "";
      updateBadge();
    }
  }
  async function fillItemCategory(
    itemId,
    revision,
    category,
    userGesture = null,
    clickedTab = null,
  ) {
    const kind = core.normalizeCategory(category);
    if (kind !== "card" && kind !== "identity") {
      status = "此条目类别不支持填充";
      return;
    }
    if (kind === "card" && !userGestureValid(userGesture)) {
      status = "本次信用卡填充需要明确的用户操作";
      return;
    }
    // The card menu entry is authorized only for the exact tab Chrome reported
    // for that click; a missing or malformed tab identity binds nothing.
    if (
      kind === "card" &&
      !(
        clickedTab &&
        typeof clickedTab === "object" &&
        !Array.isArray(clickedTab) &&
        Number.isSafeInteger(clickedTab.id) &&
        clickedTab.id > 0 &&
        Number.isSafeInteger(clickedTab.windowId) &&
        clickedTab.windowId > 0
      )
    ) {
      status = "本次信用卡填充需要明确的用户操作";
      return;
    }
    if (
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey ||
      !vaultItems.some(
        (item) => item.id === itemId && item.revision === revision,
      )
    ) {
      status = "条目已变化，请刷新后重试";
      return;
    }
    const generation = epoch;
    let response = null;
    const intent = { kind: "profile", itemId, revision, injectionStarted: false };
    pending = intent;
    try {
      const c = await captureTopDocument();
      // Bind the menu click's nonce to the tab and document the browser
      // reports before any native request leaves, and require that context to
      // be the tab Chrome attached to the click itself.
      if (
        kind === "card" &&
        (c.tabId !== clickedTab.id || c.windowId !== clickedTab.windowId)
      )
        throw Error("refused");
      if (kind === "card" && !consumeUserGesture(userGesture, c))
        throw Error("refused");
      await current(c);
      const profileKind = kind === "card" ? "credit_card" : "identity";
      const match = await request(
        "match-profiles",
        { ...fields(c), profile_kind: profileKind },
        35000,
      );
      if (
        generation !== epoch ||
        pending !== intent ||
        !match ||
        match.type !== "profiles" ||
        !Array.isArray(match.profiles) ||
        match.profiles.length > 100 ||
        !match.profiles.some(
          (row) =>
            row &&
            row.id === itemId &&
            row.revision === revision &&
            row.category === profileKind,
        )
      )
        throw Error("refused");
      response = await request(
        "fill-profile",
        { ...fields(c), item_id: itemId, revision },
        35000,
      );
      if (generation !== epoch || pending !== intent) throw Error("refused");
      const fill = response.profile_fill;
      if (
        !fill ||
        fill.item_id !== itemId ||
        fill.revision !== revision ||
        fill.category !== profileKind ||
        !fill.fields ||
        typeof fill.fields !== "object" ||
        Array.isArray(fill.fields)
      )
        throw Error("refused");
      await current(c);
      if (generation !== epoch || pending !== intent) throw Error("refused");
      intent.injectionStarted = true;
      let results;
      try {
        results = await api.scripting.executeScript({
          target: { tabId: c.tabId, documentIds: [c.documentId] },
          func:
            kind === "card"
              ? core.fillCheckoutCardDocument
              : core.fillIdentityDocument,
          args:
            kind === "card"
              ? [c.origin, fill.fields, Date.now() + 1500, true, true]
              : [c.origin, fill.fields, Date.now() + 1500, false, "identity"],
        });
      } finally {
        wipeMap(fill.fields);
        if (response.profile_fill) {
          wipeMap(response.profile_fill.fields);
          response.profile_fill.fields = {};
        }
      }
      const result = results?.length === 1 ? results[0]?.result : null;
      if (
        generation !== epoch ||
        pending !== intent ||
        !Array.isArray(results) ||
        results.length !== 1 ||
        results[0].frameId !== 0 ||
        results[0].documentId !== c.documentId ||
        (kind === "card"
          ? !result ||
            typeof result !== "object" ||
            Array.isArray(result) ||
            Object.keys(result).sort().join(",") !== "count,filled" ||
            result.filled !== true ||
            !Number.isSafeInteger(result.count) ||
            result.count < 1 ||
            result.count > CHECKOUT_MAX_FRAMES
          : result !== true)
      )
        throw Error("refused");
      intent.injectionStarted = false;
      fillUnknown = false;
      status =
        kind === "card"
          ? "已请求填充所选银行卡；未自动提交；请核实网站结果"
          : "已请求填充所选身份信息；未自动提交；请核实网站结果";
    } catch {
      if (generation === epoch && pending === intent) {
        fillUnknown = intent.injectionStarted === true;
        status = fillUnknown
          ? FILL_UNKNOWN
          : "此原生宿主暂不支持填充该条目类别";
      }
    } finally {
      if (response?.profile_fill) {
        if (response.profile_fill.fields) wipeMap(response.profile_fill.fields);
        response.profile_fill.fields = {};
      }
      if (generation === epoch && pending === intent) pending = null;
      updateBadge();
    }
  }
  function publicHistory(entries) {
    if (!Array.isArray(entries)) return [];
    return entries.slice(0, 20).map((entry, index) => ({
      index: Number.isInteger(entry?.index) ? entry.index : index,
      timestamp: Number.isInteger(entry?.timestamp) ? entry.timestamp : 0,
      action:
        typeof entry?.action === "string" ? entry.action.slice(0, 64) : "",
      title:
        typeof entry?.title === "string" ? entry.title.slice(0, 256) : "",
      username:
        typeof entry?.username === "string"
          ? entry.username.slice(0, 256)
          : "",
      has_password: entry?.has_password === true,
    }));
  }
  function candidateItems() {
    if (!context?.origin) return [];
    return rows
      .map((row) =>
        publicItem({
          ...row,
          category: "login",
          urls: [context.origin],
          state: "active",
        }),
      )
      .filter(Boolean);
  }
  async function vaultSearch(rawQuery, rawCategory, rawPasskeysOnly, rawStateFilter) {
    if (!capability) throw Error("refused");
    const generation = ++vaultSearchGeneration,
      requestEpoch = epoch,
      requestCapability = capability;
    const current = () =>
      generation === vaultSearchGeneration &&
      requestEpoch === epoch &&
      requestCapability === capability;
    const passkeysOnly = rawPasskeysOnly === true;
    if (passkeysOnly && !passkeyManagementSupported()) {
      if (!current())
        return {
          items: [],
          source: "stale",
          fallback: false,
          unsupported: false,
          stale: true,
        };
      vaultItems = [];
      status = "当前原生宿主不支持 Passkey 管理，请升级原生宿主";
      return { items: [], source: "unsupported", fallback: false, unsupported: true };
    }
    const category = core.validCategory(rawCategory) ? rawCategory : "all";
    const stateFilter = ["active", "archived", "trashed", "all"].includes(
      rawStateFilter,
    )
      ? rawStateFilter
      : "";
    const query =
      typeof rawQuery === "string" ? rawQuery.slice(0, 500) : "";
    // The native wire uses canonical v2 categories; normalizeCategory()
    // returns UI aliases such as "card" and would filter every card out.
    const wireCategory = core.nativeCategory(category);
    try {
      const response = await request(
        "vault-search",
        {
          capability,
          query,
          category: wireCategory,
          favorites_only: category === "favorites",
          ...(stateFilter ? { state: stateFilter } : {}),
          ...(passkeysOnly ? { passkeys_only: true } : {}),
        },
        12000,
      );
      if (!current())
        return {
          items: [],
          source: "stale",
          fallback: false,
          unsupported: false,
          stale: true,
        };
      const items = [];
      for (const item of response.items || []) {
        const publicEntry = publicItem(item);
        if (publicEntry) items.push(publicEntry);
      }
      vaultItems = items.slice(0, 500);
      status = passkeysOnly
        ? `金库中有 ${vaultItems.length} 个 Passkey`
        : `金库中有 ${vaultItems.length} 个条目`;
      return { items: vaultItems, source: "native", fallback: false };
    } catch {
      if (!current())
        return {
          items: [],
          source: "stale",
          fallback: false,
          unsupported: false,
          stale: true,
        };
      if (passkeysOnly) {
        vaultItems = [];
        status = "Passkey 列表读取失败，请重新连接后重试";
        return { items: [], source: "native", fallback: false, unsupported: false };
      }
      vaultItems = candidateItems();
      status = vaultItems.length
        ? "当前原生宿主仅提供当前网站候选"
        : "当前原生宿主不支持浏览完整金库";
      return {
        items: vaultItems,
        source: "candidates",
        fallback: true,
      };
    }
  }
  async function removePasskey(message) {
    if (
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "") ||
      !core.validCredentialID(message.credential_id) ||
      (message.credential_revision !== undefined &&
        !core.validCredentialRevision(message.credential_revision))
    ) {
      const refused = Error("refused");
      refused.knownRefusal = true;
      refused.keepStatus = true;
      throw refused;
    }
    if (!passkeyManagementSupported()) {
      status = "当前原生宿主不支持 Passkey 管理，请升级原生宿主";
      const error = Error("refused");
      error.knownRefusal = true;
      error.keepStatus = true;
      throw error;
    }
    let response;
    try {
      response = await request(
        "passkey-remove",
        {
          capability,
          item_id: message.id,
          revision: message.revision,
          credential_id: message.credential_id,
          ...(message.credential_revision
            ? { credential_revision: message.credential_revision }
            : {}),
        },
        20000,
      );
    } catch (error) {
      if (!error.knownRefusal) {
        const uncertain = Error("unknown");
        uncertain.uncertain = true;
        throw uncertain;
      }
      throw error;
    }
    if (response?.type === "unknown") {
      const uncertain = Error("unknown");
      uncertain.uncertain = true;
      throw uncertain;
    }
    if (
      !core.validResponse(response) ||
      response.type !== "passkey-removed" ||
      response.item_id !== message.id ||
      response.credential_id !== message.credential_id
    ) {
      const uncertain = Error("unknown");
      uncertain.uncertain = true;
      throw uncertain;
    }
    vaultSearchGeneration++;
    vaultItems = [];
    detailCache.clear();
    status = "Passkey 已删除；登录和其他信息已保留";
    updateBadge();
    rebuildContextMenus();
    return {
      item_id: response.item_id,
      revision: response.revision,
      credential_id: response.credential_id,
    };
  }
  async function getVaultItem(itemId, revision) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(itemId || "") ||
      !/^[a-f0-9]{64}$/.test(revision || "")
    )
      throw Error("refused");
    const key = itemId + ":" + revision;
    try {
      const response = await request(
        "item-get",
        { capability, item_id: itemId, revision },
        12000,
      );
      const detail = publicDetail(response.item);
      if (!detail) throw Error("refused");
      detailCache.set(key, detail);
      return detail;
    } catch {
      const row = rows.find(
        (candidate) =>
          candidate.id === itemId && candidate.revision === revision,
      );
      if (!row) throw Error("refused");
      const detail = publicDetail({
        ...row,
        category: "login",
        urls: context?.origin ? [context.origin] : [],
        state: "active",
        fields: [],
      });
      if (!detail) throw Error("refused");
      detail.readOnly = true;
      detail.unavailable = "当前原生宿主不提供条目详情";
      detailCache.set(key, detail);
      return detail;
    }
  }
  async function addSiteToItem(message) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "") ||
      typeof message.origin !== "string"
    )
      throw Error("refused");
    let origin;
    try {
      origin = core.originFromURL(message.origin);
    } catch {
      throw Error("refused");
    }
    if (origin !== message.origin || !origin.startsWith("https://"))
      throw Error("refused");
    const detail = await request(
      "item-get",
      { capability, item_id: message.id, revision: message.revision },
      12000,
    );
    const item = detail.item;
    if (
      !item ||
      item.id !== message.id ||
      item.revision !== message.revision ||
      !["login", "password"].includes(item.category)
    )
      throw Error("refused");
    const existing = Array.isArray(item.urls) ? item.urls : [];
    const originOf = (entry) => {
      try {
        return core.originFromURL(
          typeof entry === "string" ? entry : entry?.url,
        );
      } catch {
        return "";
      }
    };
    if (existing.some((entry) => originOf(entry) === origin))
      throw Error("refused");
    if (existing.length >= 20) throw Error("refused");
    // Preserve labels, primary flags and match modes; only append one origin.
    const urls = existing.map((entry) => ({
      url: typeof entry === "string" ? entry : String(entry?.url || ""),
      ...(typeof entry === "object" && entry?.label
        ? { label: String(entry.label).slice(0, 256) }
        : {}),
      ...(typeof entry === "object" && entry?.primary === true
        ? { primary: true }
        : {}),
      match_mode:
        typeof entry === "object" &&
        ["origin", "host", "exact"].includes(entry?.match_mode)
          ? entry.match_mode
          : "origin",
    }));
    urls.push({ url: origin, match_mode: "origin" });
    const itemJSON = JSON.stringify({
      category: item.category,
      title: item.title,
      urls,
    });
    const response = await request(
      "item-save",
      {
        capability,
        item_id: message.id,
        revision: message.revision,
        item_json: itemJSON,
      },
      20000,
    );
    if (
      response.type !== "item-saved" ||
      response.item_id !== message.id ||
      !/^[a-f0-9]{64}$/.test(response.revision || "")
    )
      throw Error("refused");
    detailCache.clear();
    vaultItems = [];
    status = "已添加到当前网站";
    return {
      saved: { item_id: response.item_id, revision: response.revision },
      origin,
    };
  }
  async function saveVaultItem(message) {
    if (!capability || !core.validItemForSave(message.item))
      throw Error("refused");
    const mode = message.mode === "edit" ? "edit" : "create";
    if (
      mode === "edit" &&
      (!/^[a-f0-9]{32}$/.test(message.id || "") ||
        !/^[a-f0-9]{64}$/.test(message.revision || ""))
    )
      throw Error("refused");
    let itemJSON;
    try {
      const original =
        mode === "edit"
          ? detailCache.get(message.id + ":" + message.revision) || null
          : null;
      const mutation = core.itemToNativeMutation(message.item, { original });
      if (!mutation) throw Error("refused");
      itemJSON = JSON.stringify(mutation);
    } catch {
      throw Error("refused");
    }
    if (
      typeof itemJSON !== "string" ||
      new TextEncoder().encode(itemJSON).length > 65536
    )
      throw Error("refused");
    let response;
    try {
      response = await request(
        "item-save",
        {
          capability,
          ...(mode === "edit"
            ? { item_id: message.id, revision: message.revision }
            : {}),
          item_json: itemJSON,
        },
        20000,
      );
    } catch {
      const error = Error("refused");
      error.keepStatus = true;
      status = "当前原生宿主不支持在扩展中保存条目";
      throw error;
    } finally {
      itemJSON = "";
    }
    if (
      !/^[a-f0-9]{32}$/.test(response.item_id || "") ||
      !/^[a-f0-9]{64}$/.test(response.revision || "")
    )
      throw Error("refused");
    status = "已保存";
    vaultSearchGeneration++;
    vaultItems = [];
    detailCache.clear();
    updateBadge();
    rebuildContextMenus();
    return { item_id: response.item_id, revision: response.revision };
  }
  function expireOTPCaptures() {
    const now = Date.now();
    for (const [key, capture] of otpCaptures) {
      if (now - capture.at > OTP_CAPTURE_TTL) otpCaptures.delete(key);
    }
    while (otpCaptures.size > OTP_CAPTURE_LIMIT) {
      const oldest = [...otpCaptures.entries()].sort(
        (left, right) => left[1].at - right[1].at,
      )[0];
      if (!oldest) break;
      otpCaptures.delete(oldest[0]);
    }
  }
  // A page may show a two-factor setup QR code. The content script decodes it
  // with BarcodeDetector and sends the otpauth text here. Nothing is written:
  // the validated text and the exact document's login candidates are kept in
  // worker memory, and the page only receives the display label plus item
  // titles. A later save must name this capture ID and one of those items.
  async function captureOTPForContent(message, c) {
    if (!capability || pending || pendingOTP || pendingPasskey)
      return { ok: false, reason: "busy" };
    const parsed = core.parseOTPAuthTOTP(message.otpauth);
    if (!parsed) return { ok: false, reason: "invalid" };
    if (
      !core.sameContext(c, context) ||
      matchCategory !== "login" ||
      Date.now() - lastMatchAt > 5000
    ) {
      await match("login", c.frameId);
      lastMatchAt = Date.now();
    }
    await current(c);
    const candidates = rows
      .filter((row) => rowCategory(row) === "login")
      .slice(0, 10)
      .map((row) => ({
        id: row.id,
        revision: row.revision,
        title: row.title || "",
      }));
    if (!candidates.length) return { ok: false, reason: "no-item" };
    expireOTPCaptures();
    const captureId = id();
    otpCaptures.set(captureId, {
      config: String(message.otpauth).trim(),
      origin: c.origin,
      tabId: c.tabId,
      documentId: c.documentId,
      candidates,
      at: Date.now(),
    });
    expireOTPCaptures();
    return {
      ok: true,
      captureId,
      label: parsed.label,
      items: candidates.map((row) => ({ id: row.id, title: row.title })),
    };
  }
  // Saves one captured TOTP configuration into an existing login. The target
  // item must be one of the candidates observed for this exact document, and
  // the whole mutation is written by the existing native item-edit path, which
  // re-reads the item under its revision, validates the otpauth text again and
  // preserves every field this mutation does not name.
  async function saveCapturedOTP(message, c) {
    const capture = otpCaptures.get(message.captureId);
    if (!capture) return { ok: false, reason: "expired" };
    if (Date.now() - capture.at > OTP_CAPTURE_TTL) {
      otpCaptures.delete(message.captureId);
      return { ok: false, reason: "expired" };
    }
    // A capture belongs to one exact document. A different tab, origin or
    // document may not spend it; the owner document keeps its chance.
    if (
      capture.origin !== c.origin ||
      capture.tabId !== c.tabId ||
      capture.documentId !== c.documentId
    )
      return { ok: false, reason: "expired" };
    if (!/^[a-f0-9]{32}$/.test(message.itemId || ""))
      return { ok: false, reason: "item" };
    if (!capability) {
      otpCaptures.delete(message.captureId);
      return { ok: false, reason: "locked" };
    }
    const target = capture.candidates.find((row) => row.id === message.itemId);
    if (!target) return { ok: false, reason: "item" };
    const itemJSON = JSON.stringify({
      title: target.title,
      category: "login",
      otp: capture.config,
    });
    if (new TextEncoder().encode(itemJSON).length > 32768)
      return { ok: false, reason: "invalid" };
    let response;
    try {
      response = await request(
        "item-save",
        {
          capability,
          item_id: target.id,
          revision: target.revision,
          item_json: itemJSON,
        },
        20000,
      );
    } catch {
      return { ok: false, reason: "host" };
    }
    if (
      !["item-saved", "saved"].includes(response?.type) ||
      response.item_id !== target.id ||
      !/^[a-f0-9]{64}$/.test(response.revision || "")
    )
      return { ok: false, reason: "host" };
    otpCaptures.delete(message.captureId);
    rows = rows.map((row) =>
      row.id === response.item_id ? { ...row, revision: response.revision } : row,
    );
    vaultSearchGeneration++;
    detailCache.clear();
    updateBadge();
    return { ok: true, revision: response.revision };
  }
  async function setItemState(message) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    const state = ["active", "archived", "trashed"].includes(message.state)
      ? message.state
      : undefined;
    const favorite =
      typeof message.favorite === "boolean" ? message.favorite : undefined;
    if (!state && favorite === undefined) throw Error("refused");
    const known =
      vaultItems.find((item) => item.id === message.id)?.state ||
      detailCache.get(message.id + ":" + message.revision)?.state ||
      "active";
    const actions = [];
    if (state && state !== known) {
      if (state === "archived") actions.push("archive");
      else if (state === "trashed") actions.push("trash");
      else if (known === "archived") actions.push("unarchive");
      else if (known === "trashed") actions.push("untrash");
    }
    if (favorite !== undefined)
      actions.push(favorite ? "favorite" : "unfavorite");
    if (!actions.length) throw Error("refused");
    let response = { revision: message.revision };
    try {
      for (const action of actions) {
        response = await request(
          "item-state",
          {
            capability,
            item_id: message.id,
            revision: response.revision,
            state_action: action,
          },
          15000,
        );
        if (!["item-saved", "saved"].includes(response.type))
          throw Error("refused");
      }
    } catch {
      const error = Error("refused");
      error.keepStatus = true;
      status = "当前原生宿主不支持修改条目状态";
      throw error;
    }
    status = state === "trashed" ? "条目已移至废纸篓" : "条目已更新";
    vaultSearchGeneration++;
    vaultItems = vaultItems.map((item) =>
      item.id === message.id
        ? {
            ...item,
            revision: response.revision,
            ...(state ? { state } : {}),
            ...(favorite === undefined ? {} : { favorite }),
          }
        : item,
    );
    const cached = detailCache.get(message.id + ":" + message.revision);
    if (cached)
      detailCache.set(message.id + ":" + response.revision, {
        ...cached,
        revision: response.revision,
        ...(state ? { state } : {}),
        ...(favorite === undefined ? {} : { favorite }),
      });
    updateBadge();
    rebuildContextMenus();
    return { revision: response.revision };
  }
  async function fieldValue(message, copy) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    const field = message.field || message.field_id;
    if (
      typeof field !== "string" ||
      !/^(?:username|password|notes|url|otp|cc-number|cc-csc|cc-pin|section:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128})$/.test(field)
    )
      throw Error("refused");
    const detail =
      detailCache.get(message.id + ":" + message.revision) ||
      (await getVaultItem(message.id, message.revision));
    if (!core.flattenItemFields(detail).some((entry) => entry.id === field))
      throw Error("refused");
    const response = await request(
      copy ? "item-copy-field" : "item-reveal-field",
      {
        capability,
        item_id: message.id,
        revision: message.revision,
        field,
        action: copy ? "copy" : "reveal",
      },
      12000,
    );
    if (!core.validResponse(response) || response.type !== "field-value")
      throw Error("refused");
    const hostExpires = Number.isSafeInteger(response.expires_in_seconds)
      ? Math.max(0, response.expires_in_seconds)
      : 0;
    // Non-OTP reveal has no host window. Use a bounded local 30s window,
    // while OTP must never outlive the host-provided TOTP window.
    const expires = copy
      ? hostExpires > 0
        ? Math.min(30, hostExpires)
        : 30
      : response.field === "otp"
        ? hostExpires
        : hostExpires > 0
          ? Math.min(30, hostExpires)
          : 30;
    return {
      field: response.field,
      value: response.value,
      revision: response.revision,
      expires_in_seconds: expires,
      copied: response.copied,
      clearAfterSeconds: expires,
    };
  }
  async function copyFieldValue(message) {
    return fieldValue(message, true);
  }

  /* ---------------------------------------------------------------- *
   * Persistent approval routes.                                       *
   *                                                                   *
   * An ordinary (non-QuickFill) vault row must not start `item-get`    *
   * from the action popup: native desktop V2 focuses the desktop app, *
   * Chrome destroys that popup and the approved detail is lost. The   *
   * popup first asks for a route tab that shows the same popup UI.    *
   * Only this worker's memory knows the target and the source page.   *
   * ---------------------------------------------------------------- */
  const ROUTE_URL = (api.runtime.getURL || ((path) => path))("popup.html");
  function routeURL(token) {
    return ROUTE_URL + "#route=" + token;
  }
  // The browser's own tab identity: the extension page itself, no query, no
  // other extension document. The fragment (the route token) is not part of
  // the identity check; the worker's map decides which token is live.
  function routePageURL(sender, tab) {
    if (!sender?.tab || sender.id !== api.runtime.id) return "";
    if (typeof sender.url !== "string" || typeof tab?.url !== "string") return "";
    if (sender.url.split("#")[0] !== ROUTE_URL) return "";
    if (tab.url.split("#")[0] !== ROUTE_URL) return "";
    if (sender.frameId !== 0 || sender.tab.id !== tab.id) return "";
    // No origin comparison: a chrome-extension: URL has an opaque origin
    // (new URL(...).origin === "null"). The runtime id plus these exact
    // extension URLs are the authoritative identity.
    return sender.tab.url;
  }
  // Exactly one exact fragment token, nothing else.
  function routeTokenFromPage(pageURL) {
    const match = /^[^#]*#route=([a-f0-9]{64})$/.exec(pageURL || "");
    return match ? match[1] : "";
  }
  // A grant still exists, still belongs to this exact page regardless of the
  // fragment the page claims, and still holds the live capability/epoch. It
  // is live while open and after its single claim has moved it to claimed, so
  // the approved read that the claim started can finish.
  function routeLive(grant) {
    return (
      !!grant &&
      routeGrants.get(grant.token) === grant &&
      (grant.state === "open" || grant.state === "claimed") &&
      grant.expiresAt > Date.now() &&
      grant.capability !== "" &&
      grant.capability === capability &&
      grant.epoch === epoch &&
      (routeTabs.get(grant.tabId) || null) === grant
    );
  }
  // Revocation only drops worker memory. It never closes, navigates or
  // scripts the route tab (or any page): the page learns `revoked` on its own
  // port, or its next request is refused.
  function revokeRoute(grant) {
    if (!grant) return;
    const known =
      routeGrants.get(grant.token) === grant ||
      routeTabs.get(grant.tabId) === grant ||
      routeBoots.has(grant);
    routeGrants.delete(grant.token);
    routeBoots.delete(grant);
    if ((routeTabs.get(grant.tabId) || null) === grant) routeTabs.delete(grant.tabId);
    // Every route port loses its unused native grant and the approved field
    // selectors; nothing it still holds can authorize a prepare or commit.
    for (const state of grant.clients) {
      clipboardDropGrant(state, true);
      state.routeDetail = null;
    }
    grant.clients.clear();
    grant.routeDetail = null;
    // Tell this route's own page that it is dead, then close the channel. No
    // detail or value ever travels here: only the token.
    const lifecycle = [...(grant.lifecyclePorts || [])];
    grant.lifecyclePorts?.clear();
    for (const state of lifecycle) {
      routeLifecyclePorts.delete(state);
      try {
        state.port.postMessage({ type: "route-revoked", token: grant.token });
      } catch {}
      try {
        state.port.disconnect();
      } catch {}
    }
    if (known) grant.state = "revoked";
  }
  function revokeAllRoutes() {
    routeLifecycleDiag("routes-revoked-all");
    const grants = new Set([...routeGrants.values(), ...routeTabs.values()]);
    for (const grant of grants) revokeRoute(grant);
    routeGrants.clear();
    routeTabs.clear();
  }
  function pruneRoutes() {
    for (const grant of new Set([...routeGrants.values(), ...routeTabs.values()]))
      if (grant.expiresAt <= Date.now()) {
        routeLifecycleDiag("route-expired");
        revokeRoute(grant);
      }
  }
  // Every grant counts toward ROUTE_LIMIT, whether its tab is bound or its
  // tabs.create() is still pending: a pending create holds a route slot.
  function routeGrantSet() {
    return new Set([...routeGrants.values(), ...routeTabs.values(), ...routeBoots]);
  }
  function routeGrantCount() {
    return routeGrantSet().size;
  }
  // A pending create is not yet an ordinary routeTabs entry, so routeLive()
  // is necessarily false for it; its state is checked directly. Child fields
  // are read only after the object identity of this exact boot is confirmed.
  function routeBootLive(boot) {
    return (
      !!boot &&
      routeBoots.has(boot) &&
      routeGrants.get(boot.token) === boot &&
      // Only an unbound create is a boot: bindRouteTab() moves it to
      // routeTabs and clears routeBoots in the same step.
      boot.tabId === 0 &&
      boot.state === "open" &&
      boot.expiresAt > Date.now() &&
      boot.capability !== "" &&
      boot.capability === capability &&
      boot.epoch === epoch
    );
  }
  // The route document may connect its lifecycle port before the browser
  // reports its activation or initial load and before tabs.create() resolves.
  // The exact pending boot is recognised before routeMessage() can revoke it,
  // and is verified only against the browser's own report of the created tab.
  // The sender is only ever compared structurally: Port.sender is a getter
  // that need not return the same object reference twice.
  async function bindEarlyRouteTab(sender) {
    if (
      !sender?.tab ||
      sender.id !== api.runtime.id ||
      sender.frameId !== 0 ||
      !Number.isSafeInteger(sender.tab.id) ||
      sender.tab.id < 1 ||
      typeof sender.url !== "string" ||
      typeof sender.tab.url !== "string"
    )
      return null;
    // The browser's own tab must still be exactly the tab the sender carries.
    // routePageURL() then applies the same admission contract as the ordinary
    // route path, including a sender.url that lags within this tab: only the
    // extension-page base is checked there, while the browser-reported tab is
    // the current exact page. The token is taken from that verified page only,
    // never from the sender's own claim.
    const tab = await routeTabAt(sender.tab.id, sender.tab.url);
    if (!tab) {
      routeLifecycleDiag("boot-bind-browser-tab-missing");
      return null;
    }
    const pageURL = routePageURL(sender, tab);
    if (!pageURL || pageURL !== tab.url) {
      routeLifecycleDiag("boot-bind-page-mismatch");
      return null;
    }
    const token = routeTokenFromPage(pageURL);
    if (!token) {
      routeLifecycleDiag("boot-bind-page-mismatch");
      return null;
    }
    const boots = [...routeBoots].filter(
      (candidate) => candidate.token === token,
    );
    // Equal tokens cannot share this set, so a single match is the routed
    // grant: safe to hand to a revoking check before it is re-verified.
    const boot = boots.length === 1 ? boots[0] : null;
    if (
      !boot ||
      boot.routeURL !== pageURL ||
      boot.routeURL !== routeURL(boot.token) ||
      // Every mutable field is read after the await: the boot may have been
      // revoked, bound by the browser's own event or claimed meanwhile.
      !routeBootLive(boot)
    ) {
      routeLifecycleDiag("boot-bind-no-unique-boot");
      return null;
    }
    // The browser's own tab must carry the exact route URL, sit in the source
    // window, be the active tab, and agree with the sender's tab window.
    if (
      tab.windowId !== boot.windowId ||
      tab.active !== true ||
      sender.tab.windowId !== tab.windowId
    ) {
      // A replaced, moved or inactive tab is not this route any more.
      routeLifecycleDiag(
        tab.windowId !== boot.windowId
          ? "boot-bind-wrong-window"
          : tab.active !== true
            ? "boot-bind-inactive-tab"
            : "boot-bind-page-mismatch",
      );
      revokeRoute(boot);
      return null;
    }
    // Bind exactly as the create continuation would once tabs.create()
    // resolves; onActivated still consumes the one permitted startup switch.
    bindRouteTab(boot, tab.id, tab.windowId);
    boot.activated = true;
    boot.initialLoad = null;
    routeLifecycleDiag("boot-bind-bound");
    return { boot, tabId: tab.id, windowId: tab.windowId };
  }
  async function routeTabAt(tabId, expectedURL) {
    if (!Number.isSafeInteger(tabId) || tabId < 1 || !expectedURL) return null;
    try {
      const tab = await api.tabs.get(tabId);
      if (
        !tab ||
        tab.id !== tabId ||
        typeof tab.url !== "string" ||
        tab.url !== expectedURL
      )
        return null;
      return tab;
    } catch {
      return null;
    }
  }
  async function routeSourceAt(source) {
    if (!Number.isSafeInteger(source.tabId) || source.tabId < 1) return null;
    try {
      const tab = await api.tabs.get(source.tabId);
      if (
        !tab ||
        tab.id !== source.tabId ||
        tab.windowId !== source.windowId ||
        typeof tab.url !== "string" ||
        !core.validHTTPSOrigin(core.originFromURL(tab.url)) ||
        core.originFromURL(tab.url) !== source.origin ||
        // The exact captured URL includes path, query and fragment. A reload
        // that keeps the URL is caught by the load event below.
        tab.url !== source.url
      )
        return null;
      return tab;
    } catch {
      return null;
    }
  }
  // Both anchors are re-read after every await: a closed, moved or retargeted
  // route tab and a navigated, closed or moved source page both revoke. Only
  // the route tab must be the active tab; opening it makes the captured
  // source inactive, so the source only has to stay the same tab in its
  // window at the exact captured URL and origin. A reload at the same URL is
  // caught by the source tab's load event, never by inventing document data.
  async function routeAnchors(grant) {
    if (grant.epoch !== epoch || grant.capability !== capability) return false;
    const [tab, source] = await Promise.all([
      routeTabAt(grant.tabId, grant.routeURL),
      routeSourceAt(grant.source),
    ]);
    return (
      !!tab &&
      tab.windowId === grant.windowId &&
      tab.active === true &&
      !!source
    );
  }
  function requireRoute(grant) {
    if (!routeLive(grant)) {
      revokeRoute(grant);
      throw Error("refused");
    }
  }
  async function revalidateRoute(grant) {
    requireRoute(grant);
    if (!(await routeAnchors(grant))) {
      revokeRoute(grant);
      throw Error("refused");
    }
    requireRoute(grant);
  }
  // Called after every await that yields while a route-owned native response
  // may be in flight. A revoked route discards the response before it can
  // reach the popup cache or the page.
  async function routeSettled(grant) {
    try {
      if (!routeLive(grant) || !(await routeAnchors(grant))) revokeRoute(grant);
    } catch {
      revokeRoute(grant);
    }
  }
  async function createRoute(message, sender) {
    await settingsReady;
    const allowed = ["type", "id", "revision", "quick_fill"];
    if (
      !capability ||
      !message ||
      Object.keys(message).some((key) => !allowed.includes(key)) ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "") ||
      // QuickFill keeps its existing direct detail path; a route is only for
      // the native V2 approval flow of an ordinary click.
      (message.quick_fill !== undefined && message.quick_fill !== false)
    )
      throw Error("refused");
    // Only this extension's action popup (no tab) may create a route, and the
    // source is the HTTPS top document the worker captured for `match`.
    if (!sender || sender.id !== api.runtime.id || sender.tab || sender.url !== ROUTE_URL)
      throw Error("refused");
    const source = context,
      sourceTab = source ? await routeSourceAt(source) : null;
    if (
      !source ||
      !sourceTab ||
      !Number.isSafeInteger(source.tabId) ||
      source.tabId < 1 ||
      !Number.isSafeInteger(source.windowId) ||
      source.windowId < 1 ||
      source.frameId !== 0 ||
      typeof source.documentId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(source.documentId) ||
      typeof source.origin !== "string" ||
      core.originFromURL(source.origin) !== source.origin ||
      !core.validHTTPSOrigin(source.origin) ||
      typeof source.url !== "string" ||
      // The page must not have moved since match captured it.
      source.url !== sourceTab.url ||
      // A pending fill, OTP or open-and-fill owns the source page; a route
      // must not be created underneath it.
      pending ||
      pendingOTP ||
      pendingPasskey ||
      pendingOpenAndFill
    )
      throw Error("refused");
    const requestEpoch = epoch,
      requestCapability = capability,
      requestSource = {
        tabId: source.tabId,
        windowId: source.windowId,
        documentId: source.documentId,
        origin: source.origin,
        url: source.url,
      };
    // The source may have moved while it was read; the route now binds the
    // captured document and the browser-checked same tab/window/URL/origin.
    if (requestEpoch !== epoch || requestCapability !== capability || !capability)
      throw Error("refused");
    pruneRoutes();
    for (const existing of new Set([...routeGrants.values(), ...routeTabs.values()]))
      if (existing.source.tabId === requestSource.tabId && existing.itemId === message.id)
        revokeRoute(existing);
    while (routeGrantCount() >= ROUTE_LIMIT) {
      const oldest = [...routeGrantSet()].sort(
        (left, right) => left.expiresAt - right.expiresAt,
      )[0];
      if (!oldest) break;
      revokeRoute(oldest);
    }
    const token = id() + id();
    const grant = {
      token,
      itemId: message.id,
      revision: message.revision,
      source: requestSource,
      tabId: 0,
      windowId: sourceTab.windowId,
      routeURL: "",
      capability: requestCapability,
      epoch: requestEpoch,
      state: "open",
      expiresAt: Date.now() + ROUTE_TTL,
      clients: new Set(),
      lifecyclePorts: new Set(),
    };
    grant.routeURL = routeURL(token);
    grant.windowId = sourceTab.windowId;
    // Registered before tabs.create: the browser may report this tab's
    // activation and initial load before that promise resolves.
    routeGrants.set(token, grant);
    routeBoots.add(grant);
    let created;
    try {
      // The route must stay in the captured source tab's window.
      created = await api.tabs.create({
        url: routeURL(token),
        active: true,
        windowId: sourceTab.windowId,
      });
    } catch {
      routeLifecycleDiag("route-create-failed");
      revokeRoute(grant);
      throw Error("refused");
    }
    if (!created || !Number.isSafeInteger(created.id) || created.id < 1) {
      routeLifecycleDiag("route-create-invalid-tab");
      revokeRoute(grant);
      throw Error("refused");
    }
    // A lock, disconnect, source navigation or cap eviction may have revoked
    // this grant while tabs.create() was in flight. The browser may already
    // have opened the tab, so fail closed without binding, returning or
    // closing it.
    // A lifecycle port admitted from this still-pending boot has already
    // bound the very tab the browser returns: that is the same route, not a
    // second one. The page may also have claimed its single read already, so
    // "claimed" is this same live route; revocation sets "revoked" and still
    // fails closed here.
    const adoptedByPort =
      grant.tabId === created.id &&
      routeTabs.get(grant.tabId) === grant &&
      (grant.state === "open" || grant.state === "claimed") &&
      [...grant.lifecyclePorts].some((state) => state.early === true);
    const stillOwned =
      routeGrants.get(grant.token) === grant &&
      ((grant.state === "open" &&
        ((grant.tabId === 0 && routeBoots.has(grant)) ||
          (grant.tabId !== 0 && routeTabs.get(grant.tabId) === grant))) ||
        adoptedByPort);
    if (!stillOwned) {
      routeLifecycleDiag("route-create-not-owned");
      revokeRoute(grant);
      throw Error("refused");
    }
    if (grant.tabId === 0) {
      // No activation event was observed: bind what the browser returned. The
      // grant is live only once the route tab is the active tab (checked by
      // every claim, copy and read through routeAnchors()).
      bindRouteTab(grant, created.id, created.windowId);
    } else if (grant.tabId !== created.id) {
      routeLifecycleDiag("route-create-tab-mismatch");
      revokeRoute(grant);
      throw Error("refused");
    } else {
      routeBoots.delete(grant);
    }
    return {
      type: "route-created",
      token,
      tab_id: grant.tabId,
      expires_in_seconds: Math.floor(ROUTE_TTL / 1000),
    };
  }
  async function routeClaim(message, grant) {
    if (
      !grant ||
      Object.keys(message).sort().join(",") !== "token,type" ||
      message.token !== grant.token
    )
      throw Error("refused");
    // The state transition below is synchronous, so a concurrent second claim
    // sees "claimed" and neither claim can start a second read. There is no
    // re-read path: a duplicate claim is refused outright.
    if (grant.state !== "open") throw Error("refused");
    grant.state = "claimed";
    return routeApprovedDetail(grant);
  }
  // The same native V2 `item-get` the action popup used, under a fresh native
  // list row: the route names the exact item and revision, the host decides
  // and approves. There is no field-cache or candidate fallback, and the
  // result is never written to detailCache.
  async function routeApprovedDetail(grant) {
    requireRoute(grant);
    const requestEpoch = epoch,
      requestCapability = capability,
      list = await request(
        "vault-search",
        {
          capability: requestCapability,
          query: "",
          category: "all",
          state: "all",
        },
        12000,
      );
    requireRoute(grant);
    if (
      requestEpoch !== epoch ||
      requestCapability !== capability ||
      !list ||
      // The native host answers vault-search with "vault-items"; the full DTO
      // and the exact row are still validated below.
      list.type !== "vault-items" ||
      !core.validResponse(list)
    )
      throw Error("refused");
    const row = list.items.find(
      (item) =>
        item &&
        !Array.isArray(item) &&
        item.id === grant.itemId &&
        item.revision === grant.revision,
    );
    if (!row) throw Error("refused");
    if (!(await routeAnchors(grant))) throw Error("refused");
    requireRoute(grant);
    const response = await request(
      "item-get",
      {
        capability: requestCapability,
        item_id: grant.itemId,
        revision: grant.revision,
      },
      12000,
    );
    const live = routeLive(grant);
    if (!live) {
      // A late approval for a revoked or locked route is scrubbed here.
      if (response && typeof response === "object") response.item = null;
      revokeRoute(grant);
      throw Error("refused");
    }
    if (
      requestEpoch !== epoch ||
      requestCapability !== capability ||
      !core.validResponse(response) ||
      response.type !== "item-detail"
    )
      throw Error("refused");
    const detail = publicDetail(response.item);
    if (
      !detail ||
      detail.id !== grant.itemId ||
      detail.revision !== grant.revision ||
      (detail.readOnly === true || detail.unavailable)
    )
      throw Error("refused");
    await routeSettled(grant);
    if (!routeLive(grant)) {
      scrubDetail(detail);
      throw Error("refused");
    }
    // Field selectors of the approved detail, kept on the grant so this
    // route's own clipboard ports get them whether they were admitted before
    // or after the claim. No field value is retained.
    setRouteDetail(grant, detail);
    return {
      type: "route-claimed",
      token: grant.token,
      item_id: grant.itemId,
      revision: grant.revision,
      expires_in_seconds: Math.max(
        0,
        Math.floor((grant.expiresAt - Date.now()) / 1000),
      ),
      detail,
    };
  }
  // The route-scoped selector binding: item id, revision and field ids only.
  // A route port gets it at admission and on claim, and loses it on revoke.
  function setRouteDetail(grant, detail) {
    grant.routeDetail = {
      id: detail.id,
      revision: detail.revision,
      fields: core.flattenItemFields(detail).map((entry) => entry.id),
    };
    for (const client of grant.clients) client.routeDetail = grant.routeDetail;
  }
  // Only a projectable value may leave a route: the public detail projection
  // with anything the user has not asked to see blanked in place.
  function scrubDetail(detail) {
    if (!detail) return;
    detail.password = "";
    detail.notes = "";
    detail.username = "";
    if (Array.isArray(detail.attachments)) detail.attachments.length = 0;
    for (const entry of Array.isArray(detail.fields) ? detail.fields : [])
      if (entry && typeof entry === "object") entry.value = "";
  }
  async function routeFieldValue(message, grant, copy) {
    const fields = copy
      ? "field,item_id,revision,token,type"
      : "field,id,item_id,revision,token,type";
    if (
      !grant ||
      !message ||
      Object.keys(message).sort().join(",") !== fields ||
      message.token !== grant.token ||
      message.item_id !== grant.itemId ||
      message.revision !== grant.revision ||
      (copy
        ? !core.validCopyFieldSelector(message.field)
        : !/^(?:username|password|notes|url|otp|cc-number|cc-csc|cc-pin|section:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128})$/.test(
            message.field || "",
          ))
    )
      throw Error("refused");
    // Field values only exist for a claimed route that is still open: copying
    // or revealing from the vault list beside the route is refused.
    requireRoute(grant);
    if (grant.state !== "claimed") throw Error("refused");
    await revalidateRoute(grant);
    const field = message.field;
    // The exact item/revision/field is re-read from the native vault under the
    // same V2 approval; the route never borrows the popup's cached detail.
    const response = await request(
      "item-get",
      { capability: grant.capability, item_id: grant.itemId, revision: grant.revision },
      12000,
    );
    requireRoute(grant);
    if (
      grant.capability !== capability ||
      !core.validResponse(response) ||
      response.type !== "item-detail"
    )
      throw Error("refused");
    const detail = publicDetail(response.item);
    if (
      !detail ||
      detail.id !== grant.itemId ||
      detail.revision !== grant.revision ||
      !core.flattenItemFields(detail).some((entry) => entry.id === field)
    )
      throw Error("refused");
    const requestEpoch = epoch,
      requestCapability = capability;
    await routeSettled(grant);
    requireRoute(grant);
    if (requestEpoch !== epoch || requestCapability !== capability)
      throw Error("refused");
    const value = await request(
      copy ? "item-copy-field" : "item-reveal-field",
      {
        capability: requestCapability,
        item_id: grant.itemId,
        revision: grant.revision,
        field,
        action: copy ? "copy" : "reveal",
      },
      12000,
    );
    const live = routeLive(grant);
    if (!live) {
      if (value && typeof value === "object") value.value = "";
      revokeRoute(grant);
      throw Error("refused");
    }
    if (
      requestEpoch !== epoch ||
      requestCapability !== capability ||
      !core.validResponse(value) ||
      value.type !== "field-value" ||
      value.item_id !== grant.itemId ||
      value.revision !== grant.revision ||
      value.field !== field ||
      typeof value.value !== "string"
    ) {
      if (value && typeof value === "object") value.value = "";
      throw Error("refused");
    }
    const hostExpires = Number.isSafeInteger(value.expires_in_seconds)
      ? Math.max(0, value.expires_in_seconds)
      : 0;
    const expires = copy
      ? hostExpires > 0
        ? Math.min(30, hostExpires)
        : 30
      : value.field === "otp"
        ? hostExpires
        : hostExpires > 0
          ? Math.min(30, hostExpires)
          : 30;
    return {
      field: value.field,
      value: value.value,
      revision: value.revision,
      expires_in_seconds: expires,
      copied: value.copied,
      clearAfterSeconds: expires,
    };
  }
  function routeClose(message, grant) {
    if (
      !grant ||
      Object.keys(message).sort().join(",") !== "token,type" ||
      message.token !== grant.token
    )
      return null;
    revokeRoute(grant);
    return { type: "route-closed", token: grant.token };
  }

  // Native clipboard leasing (capability native-clipboard-lease-v1).
  //
  // The popup is the only client. It opens one private runtime port, so no
  // content script, tab or page can ever drive a native grant. Each port owns
  // at most one outstanding grant, and every message carries fresh bounded
  // selectors: the background never borrows another popup's grant.
  const NATIVE_CLIPBOARD_PORT_NAME = "native-clipboard";
  // A route tab's own lifetime signal. It carries only the route token; it is
  // how a real worker revocation reaches the persistent page that still holds
  // the already-approved detail.
  const ROUTE_LIFECYCLE_PORT_NAME = "route-lifecycle";
  const ROUTE_LIFECYCLE_MAX_PORTS = 8;
  const routeLifecyclePorts = new Set();
  const NATIVE_CLIPBOARD_MAX_PORTS = 4;
  const NATIVE_CLIPBOARD_MAX_REQUEST_IDS = 32;
  const NATIVE_CLIPBOARD_MAX_GRANT_SECONDS = 15;
  const clipboardPorts = new Set();
  function nativeClipboardSupported() {
    return !!capability && core.nativeClipboardCapability(hostCapabilities);
  }
  function clipboardGrantIdle(state) {
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
  }
  function clipboardCancelOffer(capabilityNow, ticket) {
    if (!capabilityNow || !core.validCopyTicket(ticket)) return;
    try {
      void request(
        "cancel-copy-field",
        { capability: capabilityNow, copy_ticket: ticket },
        5000,
      ).catch(() => {});
    } catch {}
  }
  // A commit request can still be waiting in the desktop UI queue. CancelOffer
  // revokes that pending job and never clears a confirmed native clipboard lease.
  function clipboardDropGrant(state, cancel) {
    const grant = state.grant;
    state.grant = null;
    state.preparing = null;
    clipboardGrantIdle(state);
    if (!grant || !cancel) return;
    clipboardCancelOffer(grant.capability, grant.ticket);
  }
  function clipboardPortAlive(state) {
    return !state.closed && clipboardPorts.has(state);
  }
  function clipboardPortPost(state, message) {
    if (!clipboardPortAlive(state)) return false;
    try {
      state.port.postMessage(message);
      return true;
    } catch {
      state.closed = true;
      clipboardPorts.delete(state);
      clipboardDropGrant(state, true);
      return false;
    }
  }
  // A lock, disconnect or worker reconnect invalidates every grant: the old
  // capability/epoch is dead, so the popup must not commit.
  function invalidateClipboardGrants() {
    const states = [...clipboardPorts];
    clipboardPorts.clear();
    for (const state of states) {
      state.closed = true;
      clipboardDropGrant(state, true);
      try {
        state.port.postMessage({ type: "revoked" });
      } catch {}
    }
  }
  function clipboardRequestIdFresh(state, requestId) {
    return state.ids.size < NATIVE_CLIPBOARD_MAX_REQUEST_IDS &&
      /^[a-f0-9]{32}$/.test(requestId || "") && !state.ids.has(requestId);
  }
  function clipboardRememberRequestId(state, requestId) {
    if (state.ids.has(requestId)) return;
    state.ids.add(requestId);
    state.order.push(requestId);
  }
  function clipboardSelector(message) {
    return (
      /^[a-f0-9]{32}$/.test(message.item_id || "") &&
      /^[a-f0-9]{64}$/.test(message.revision || "") &&
      core.validCopyFieldSelector(message.field)
    );
  }
  // A route tab's port may only ever name that route's exact item/revision.
  // The ordinary popup port has no route and keeps its own selector check.
  function clipboardBound(state, message) {
    if (!state.route) return true;
    const grant = state.route;
    return (
      grant.clients.has(state) &&
      routeLive(grant) &&
      grant.state === "claimed" &&
      message.item_id === grant.itemId &&
      message.revision === grant.revision &&
      fieldAllowedByRouteDetail(state, message)
    );
  }
  // A route port may only ask native to prepare or copy a field the route's
  // own approved detail actually has. The remembered detail holds selectors
  // only (id/revision/field ids), never a field value.
  function fieldAllowedByRouteDetail(state, message) {
    const detail = state.routeDetail;
    return (
      !!detail &&
      detail.id === message.item_id &&
      detail.revision === message.revision &&
      detail.fields.includes(message.field)
    );
  }
  function clipboardRefused(requestId) {
    return { type: "refused", request_id: requestId, unknown: false };
  }
  async function clipboardPrepare(state, message) {
    const requestId = message.request_id;
    const route = state.route || null;
    if (
      Object.keys(message).sort().join(",") !==
        "field,item_id,request_id,revision,type" ||
      !clipboardSelector(message) ||
      !clipboardBound(state, message) ||
      !clipboardRequestIdFresh(state, requestId) ||
      state.grant ||
      state.preparing ||
      !nativeClipboardSupported()
    )
      return clipboardRefused("");
    clipboardRememberRequestId(state, requestId);
    const preparation = {};
    state.preparing = preparation;
    const requestEpoch = epoch,
      requestCapability = capability;
    let response = null;
    try {
      response = await request(
        "prepare-copy-field",
        {
          capability: requestCapability,
          item_id: message.item_id,
          revision: message.revision,
          field: message.field,
        },
        12000,
      );
    } catch {
      if (state.preparing === preparation) state.preparing = null;
      return clipboardRefused(requestId);
    }
    const seconds = Number.isSafeInteger(response?.expires_in_seconds)
      ? response.expires_in_seconds
      : 0;
    const cleanup = Number.isSafeInteger(response?.cleanup_ttl_seconds)
      ? response.cleanup_ttl_seconds
      : 0;
    if (
      requestEpoch !== epoch ||
      requestCapability !== capability ||
      !clipboardPortAlive(state) ||
      !clipboardBound(state, message) ||
      state.preparing !== preparation ||
      state.grant ||
      !core.validResponse(response) ||
      response.type !== "copy-prepared" ||
      response.item_id !== message.item_id ||
      response.revision !== message.revision ||
      response.field !== message.field ||
      seconds < 1 ||
      seconds > NATIVE_CLIPBOARD_MAX_GRANT_SECONDS ||
      cleanup < 0 ||
      cleanup > 3600
    ) {
      // A stale, mismatched or unbounded preparation never becomes a grant,
      // and its offer is dropped before anything could be committed.
      clipboardCancelOffer(requestCapability, response?.copy_ticket);
      if (state.preparing === preparation) state.preparing = null;
      return clipboardRefused(requestId);
    }
    state.preparing = null;
    state.grant = {
      ticket: response.copy_ticket,
      capability: requestCapability,
      itemId: message.item_id,
      revision: message.revision,
      field: message.field,
      epoch: requestEpoch,
      cleanupTTLSeconds: cleanup,
      expiresAt: Date.now() + seconds * 1000,
      committed: false,
    };
    state.timer = setTimeout(
      () => {
        if (state.grant && !state.grant.committed)
          clipboardDropGrant(state, true);
      },
      (seconds + 1) * 1000,
    );
    return {
      type: "prepared",
      request_id: requestId,
      item_id: message.item_id,
      revision: message.revision,
      field: message.field,
      copy_ticket: response.copy_ticket,
      expires_in_seconds: seconds,
      cleanup_ttl_seconds: cleanup,
    };
  }
  async function clipboardCommit(state, message) {
    const requestId = message.request_id;
    const grant = state.grant;
    if (
      Object.keys(message).sort().join(",") !==
        "copy_ticket,field,item_id,request_id,revision,type" ||
      !clipboardRequestIdFresh(state, requestId) ||
      !clipboardSelector(message) ||
      !clipboardBound(state, message) ||
      !grant ||
      grant.committed ||
      grant.epoch !== epoch ||
      grant.capability !== capability ||
      grant.ticket !== message.copy_ticket ||
      grant.itemId !== message.item_id ||
      grant.revision !== message.revision ||
      grant.field !== message.field ||
      grant.expiresAt <= Date.now() ||
      !nativeClipboardSupported()
    )
      return clipboardRefused(requestId);
    clipboardRememberRequestId(state, requestId);
    // Consume the commit once. Keep its ticket until the result so a popup
    // cancellation can still revoke a job waiting for native dispatch.
    grant.committed = true;
    clipboardGrantIdle(state);
    const requestEpoch = epoch,
      requestCapability = capability;
    let response = null;
    try {
      response = await request(
        "commit-copy-field",
        { capability: requestCapability, copy_ticket: grant.ticket },
        20000,
      );
    } catch {
      response = null;
    }
    const grantLive =
      state.grant === grant &&
      clipboardPortAlive(state) &&
      (!state.route || routeLive(state.route));
    if (state.grant === grant) state.grant = null;
    // An unknown outcome is reported as uncertain and never retried: the
    // desktop may already own the clipboard bytes.
    let resultState = "unknown";
    if (
      response &&
      grantLive &&
      requestEpoch === epoch &&
      requestCapability === capability &&
      core.validResponse(response) &&
      response.type === "copy-result" &&
      response.copy_ticket === grant.ticket
    )
      resultState = response.state;
    return {
      type: "result",
      request_id: requestId,
      copy_ticket: grant.ticket,
      state: resultState,
      copied: resultState === "confirmed",
      cleanup_ttl_seconds: grant.cleanupTTLSeconds,
    };
  }
  function clipboardCancel(state, message) {
    if (
      Object.keys(message).sort().join(",") !== "copy_ticket,request_id,type" ||
      !clipboardRequestIdFresh(state, message.request_id) ||
      !core.validCopyTicket(message.copy_ticket)
    )
      return null;
    clipboardRememberRequestId(state, message.request_id);
    const grant = state.grant;
    if (grant && grant.ticket === message.copy_ticket)
      clipboardDropGrant(state, true);
    return { type: "cancelled", request_id: message.request_id };
  }
  function clipboardPortMessage(state, message) {
    if (
      state.closed ||
      !message ||
      typeof message !== "object" ||
      Array.isArray(message)
    )
      return Promise.resolve(null);
    switch (message.type) {
      case "prepare":
        return clipboardPrepare(state, message);
      case "commit":
        return clipboardCommit(state, message);
      case "cancel":
        return Promise.resolve(clipboardCancel(state, message));
      default:
        return Promise.resolve(null);
    }
  }
  // A route tab's port is admitted only for the exact claimed, live route the
  // browser reports; its grants die with the route. The ordinary popup sender
  // (core.validSender) and its grants are unchanged.
  async function routeClipboardGrant(sender) {
    if (!sender?.tab || sender.id !== api.runtime.id) return null;
    if (typeof sender.url !== "string" || !sender.url.includes("#route="))
      return null;
    const tab = await routeTabAt(sender.tab.id, sender.tab.url);
    const pageURL = routePageURL(sender, tab);
    const token = routeTokenFromPage(pageURL);
    const grant = token ? routeGrants.get(token) || null : null;
    if (
      !grant ||
      !routeLive(grant) ||
      sender.tab.id !== grant.tabId ||
      // A port exists before the page can claim; the route's own tab and URL
      // are the admission, and its selector binding keeps it to one target.
      !(await routeAnchors(grant))
    ) {
      revokeRoute(grant);
      return null;
    }
    return grant;
  }
  // A route lifecycle port is bound by the browser's sender identity to one
  // live route: same extension, top frame, exact tab and exact route URL with
  // the exact token. It is opened before the claim and carries no data except
  // that token.
  async function openRouteLifecyclePort(port, sender) {
    routeLifecycleDiag("port-admit-started");
    const reject = () => {
      routeLifecycleDiag("port-refused");
      try {
        port?.disconnect?.();
      } catch {}
    };
    if (!port || port.name !== ROUTE_LIFECYCLE_PORT_NAME) return reject();
    // One slot is taken before the first await, so an unverified port cannot
    // open more than the cap. Until admission a refusal only frees the slot:
    // the route itself is untouched by a sender that has not been verified.
    const state = { port, grant: null, early: false };
    if (routeLifecyclePorts.size >= ROUTE_LIFECYCLE_MAX_PORTS) return reject();
    routeLifecyclePorts.add(state);
    port.onDisconnect?.addListener?.(() => {
      routeLifecycleDiag("port-disconnected");
      state.grant?.lifecyclePorts.delete(state);
      routeLifecyclePorts.delete(state);
      void api.runtime.lastError;
    });
    const drop = () => {
      routeLifecyclePorts.delete(state);
      return reject();
    };
    if (!sender?.tab || sender.id !== api.runtime.id || sender.frameId !== 0) {
      routeLifecycleDiag("port-sender-mismatch");
      return drop();
    }
    // The pending boot is adopted before routeMessage(): for an unbound boot
    // that call is refused and would revoke the grant first. This boot is
    // browser-verified already, so its port may arrive before the create
    // continuation binds it; that path never revokes.
    const early = await bindEarlyRouteTab(sender);
    let grant = early ? early.boot : null;
    if (!grant) {
      routeLifecycleDiag("port-admit-fallback");
      try {
        grant = await routeMessage(sender);
      } catch {}
    } else routeLifecycleDiag("port-admit-early");
    // Compare the browser-attached sender structurally; a Port getter is not
    // guaranteed to return the same object reference twice.
    const bound = port?.sender;
    if (
      !bound ||
      bound.id !== sender.id ||
      bound.url !== sender.url ||
      bound.frameId !== sender.frameId ||
      bound.tab?.id !== sender.tab.id ||
      bound.tab?.url !== sender.tab.url
    ) {
      routeLifecycleDiag("port-sender-mismatch");
      return drop();
    }
    // bindEarlyRouteTab() has already validated the pending boot against the
    // browser's own report of the created tab and adopted it exactly as the
    // create continuation would, so from here on it is an ordinary bound
    // route and the unchanged liveness and anchor checks apply.
    if (!grant || !routeLive(grant) || sender.tab.id !== grant.tabId) {
      routeLifecycleDiag("port-invalid-grant-or-tab");
      return drop();
    }
    // The route just adopted must pass the ordinary anchor checks once more,
    // after every await, before its port is admitted. A mismatch ends it.
    if (early) {
      const anchors = await routeAnchors(grant);
      if (!routeLive(grant) || sender.tab.id !== grant.tabId || !anchors) {
        routeLifecycleDiag(
          !routeLive(grant)
            ? "port-invalid-grant-or-tab"
            : sender.tab.id !== grant.tabId
              ? "port-invalid-grant-or-tab"
              : "port-anchor-mismatch",
        );
        revokeRoute(grant);
        return drop();
      }
    }
    state.grant = grant;
    state.early = !!early;
    grant.lifecyclePorts.add(state);
    try {
      port.postMessage({ type: "route-ready", token: grant.token });
      routeLifecycleDiag("port-ready-sent");
    } catch {
      revokeRoute(grant);
    }
  }

  function openClipboardPort(port, sender) {
    if (
      sender &&
      sender.id === api.runtime.id &&
      sender.tab &&
      !core.validSender(sender, api.runtime)
    ) {
      routeClipboardGrant(sender).then(
        (grant) => admitClipboardPort(port, sender, grant),
        () => admitClipboardPort(port, sender, null),
      );
      return;
    }
    admitClipboardPort(port, sender, null);
  }
  function admitClipboardPort(port, sender, route) {
    if (
      !port ||
      port.name !== NATIVE_CLIPBOARD_PORT_NAME ||
      (!route && !core.validSender(sender, api.runtime))
    ) {
      try {
        port?.disconnect?.();
      } catch {}
      return;
    }
    if (clipboardPorts.size >= NATIVE_CLIPBOARD_MAX_PORTS) {
      try {
        port.disconnect();
      } catch {}
      return;
    }
    const state = {
      port,
      grant: null,
      preparing: null,
      ids: new Set(),
      order: [],
      closed: false,
      timer: null,
      route,
    };
    clipboardPorts.add(state);
    if (route) {
      route.clients.add(state);
      // Opened after the claim (the popup's Copy click): start with the
      // grant's approved selectors; an open/unclaimed grant has none.
      if (route.routeDetail) state.routeDetail = route.routeDetail;
    }
    port.onMessage.addListener((message) => {
      clipboardPortMessage(state, message)
        .then((reply) => {
          if (reply) clipboardPortPost(state, reply);
        })
        .catch(() =>
          clipboardPortPost(state, {
            type: "refused",
            request_id: "",
            unknown: true,
          }),
        );
    });
    port.onDisconnect.addListener(() => {
      state.closed = true;
      clipboardPorts.delete(state);
      state.route?.clients.delete(state);
      clipboardDropGrant(state, true);
      void api.runtime.lastError;
    });
    clipboardPortPost(state, {
      type: "ready",
      native: nativeClipboardSupported(),
    });
  }
  async function openAndFill(message) {
    if (
      !capability ||
      !/^[a-f0-9]{32}$/.test(message.id || "") ||
      !/^[a-f0-9]{64}$/.test(message.revision || "")
    )
      throw Error("refused");
    const target = message.url;
    const expectedOrigin = core.originFromURL(target);
    let urls = Array.isArray(message.urls)
      ? message.urls
          .slice(0, 20)
          .filter((url) => typeof url === "string")
      : [];
    if (!urls.length) {
      const detail = await getVaultItem(message.id, message.revision);
      urls = detail.urls;
    }
    if (!core.itemURLAllowed({ urls }, target)) throw Error("refused");
    if (typeof api.tabs?.create !== "function") throw Error("refused");
    const created = await api.tabs.create({ url: target, active: true });
    if (!created || !Number.isSafeInteger(created.id) || created.id < 1)
      throw Error("refused");
    clearPendingOpenAndFill();
    pendingOpenAndFill = {
      tabId: created.id,
      expectedOrigin,
      itemId: message.id,
      revision: message.revision,
      expiresAt: Date.now() + 15000,
    };
    openAndFillTimer = setTimeout(() => {
      if (!pendingOpenAndFill) return;
      pendingOpenAndFill = null;
      openAndFillTimer = null;
      status = "打开并填充已超时；未执行填充";
      updateBadge();
    }, 15000);
    status = "已打开页面，等待加载后填充";
    return { tabId: created.id, origin: expectedOrigin };
  }
  async function processOpenAndFill(tabId, change) {
    const pendingFill = pendingOpenAndFill;
    if (!pendingFill || pendingFill.tabId !== tabId) return;
    if (typeof change?.url === "string") {
      let changedOrigin = "";
      try {
        changedOrigin = core.originFromURL(change.url);
      } catch {}
      if (changedOrigin && changedOrigin !== pendingFill.expectedOrigin) {
        clearPendingOpenAndFill();
        status = "打开并填充已取消：页面跳转到其他来源";
        updateBadge();
        return;
      }
    }
    if (change?.status !== "complete") return;
    if (Date.now() > pendingFill.expiresAt) {
      clearPendingOpenAndFill();
      status = "打开并填充已超时；未执行填充";
      updateBadge();
      return;
    }
    clearPendingOpenAndFill();
    try {
      const tabs = await api.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (
        tabs.length !== 1 ||
        tabs[0].id !== tabId ||
        core.originFromURL(tabs[0].url) !== pendingFill.expectedOrigin
      )
        throw Error("refused");
      await match();
      const row = rows.find(
        (candidate) =>
          candidate.id === pendingFill.itemId &&
          candidate.revision === pendingFill.revision,
      );
      if (!row) throw Error("refused");
      await fill(row.id, row.revision);
    } catch {
      status = "打开并填充未完成；请重新读取当前网站候选";
      updateBadge();
    }
  }
  function contentSender(sender) {
    try {
      return (
        sender?.id === api.runtime.id &&
        Number.isSafeInteger(sender.frameId) &&
        sender.frameId >= 0 &&
        Number.isSafeInteger(sender.tab?.id) &&
        typeof sender.documentId === "string" &&
        sender.documentId.length > 0 &&
        core.originFromURL(sender.url) === core.originFromURL(sender.tab.url)
      );
    } catch {
      return false;
    }
  }
  async function contentContext(sender) {
    const c = await captureTopDocument(sender.frameId);
    if (
      c.tabId !== sender.tab.id ||
      c.windowId !== sender.tab.windowId ||
      c.frameId !== sender.frameId ||
      c.documentId !== sender.documentId ||
      c.origin !== core.originFromURL(sender.url)
    )
      throw Error("refused");
    return c;
  }
  // WebAuthn Signal API hints are advisory: the page's own static method has
  // already settled, so nothing here can change a credential response, claim a
  // fill/OTP/Passkey/conditional slot or prompt for a connection. The hint is
  // only forwarded while the live capability, the native capability and the
  // Passkey use setting all still hold.
  function passkeySignalSupported() {
    return (
      !!capability &&
      offerUsePasskeys === true &&
      core.passkeySignalCapability(hostCapabilities)
    );
  }
  async function passkeySignal(message, c) {
    await settingsReady;
    // Only the isolated content bridge may forward a hint, and only from the
    // top frame; everything else is caller-supplied shape and is refused.
    if (
      Object.keys(message).length !== 2 ||
      Object.keys(message).some((key) => key !== "type" && key !== "options") ||
      c.frameId !== 0
    )
      throw Error("refused");
    const options = core.passkeySignalOptions(message.options);
    if (!options || !passkeySignalSupported()) throw Error("refused");
    const generation = epoch;
    await current(c);
    // The probe yields control: the epoch, capability, native capabilities,
    // settings and the actual tab/document/origin can all change. Re-check all
    // of them in one step before the single wire send, using only the browser
    // asserted context captured above.
    if (generation !== epoch || !passkeySignalSupported()) throw Error("refused");
    const requestId = id();
    const response = await request(
      "passkey-signal",
      { ...fields(c), options },
      8000,
      requestId,
    );
    if (
      generation !== epoch ||
      !core.validPasskeySignalAck(response, requestId)
    )
      throw Error("refused");
    return {};
  }
  async function fromContent(message, sender) {
    if (!message || typeof message !== "object") throw Error("refused");
    // Cancellation authenticates the original document even after navigation.
    if (message.type === "passkey-cancel") {
      if (
        pendingPasskey?.pageID === message.id &&
        pendingPasskey.tabId === sender.tab.id &&
        pendingPasskey.documentId === sender.documentId
      )
        cancelContext();
      const key = sender.tab.id + ":" + sender.documentId;
      const intent = conditionalIntents.get(key);
      if (
        intent &&
        intent.pageID === message.id &&
        intent.tabId === sender.tab.id &&
        intent.documentId === sender.documentId
      )
        conditionalIntents.delete(key);
      return {};
    }
    const c = await contentContext(sender);
    await settingsReady;
    if (message.type === "passkey-signal") return passkeySignal(message, c);
    if (message.type === "inline-state")
      return {
        connected: !!capability,
        offerSavePasskeys,
        offerUsePasskeys,
        passkeyConditionalSupported: passkeyConditionalSupported === true,
        offerSaveLogins,
        neverSaveForOrigin: neverSaveOrigins.includes(c.origin),
        suppressInline: neverSaveOrigins.includes(c.origin),
        generatorDefaults: { ...generatorDefaults },
      };
    if (message.type === "inline-connect") {
      if (!capability) await connect();
      await current(c);
      return { connected: !!capability };
    }
    if (message.type === "inline-otp-capture")
      return captureOTPForContent(message, c);
    if (message.type === "inline-otp-save") return saveCapturedOTP(message, c);
    if (message.type === "inline-pending-save")
      return { pendingSave: serializeStaged(stagedForTab(c.tabId, c.origin)) };
    if (message.type === "inline-stage-save") {
      if (
        !validCredentialText(message.password) ||
        (message.username !== undefined &&
          !validCredentialText(message.username, true))
      )
        throw Error("refused");
      const staged = await stageSave(
        {
          username: message.username || "",
          password: message.password,
          isNewPassword: message.isNewPassword === true,
          isPasswordChange: message.isPasswordChange === true,
          title: message.title,
          itemId: message.itemId,
          revision: message.revision,
        },
        c,
      );
      return {
        ...staged,
        pendingSave:
          staged.mode === "new" || staged.mode === "update"
            ? serializeStaged(stagedForTab(c.tabId, c.origin))
            : null,
      };
    }
    if (message.type === "inline-commit-staged-save") {
      if (typeof message.stageId !== "string" || !/^[a-f0-9]{32}$/.test(message.stageId))
        throw Error("refused");
      const result = await commitStagedSave(
        message.stageId,
        {
          mode: message.mode,
          itemId: message.itemId,
          revision: message.revision,
          title: message.title,
        },
        c,
      );
      return { ...result, pendingSave: null, status };
    }
    if (message.type === "inline-dismiss-save") {
      const result = await dismissStaged(
        typeof message.stageId === "string" ? message.stageId : "",
        message.neverForOrigin === true,
        c,
      );
      return { ...result, status };
    }
    if (message.type === "inline-generate") {
      const generated = await generateResult(message);
      const historyId =
        message.recordHistory === true
          ? recordGenerated(
              c.origin,
              typeof message.username === "string" ? message.username : "",
              generated,
            )
          : generated.historyId || "";
      return {
        password: generated.password,
        profile: generated.profile,
        historyId,
      };
    }
    if (message.type === "inline-generate-fill") {
      const result = await inlineGenerateFill(message, c, epoch);
      return { ...result, status };
    }
    if (message.type === "inline-match") {
      const category = message.category ?? "login";
      if (!validCategory(category)) throw Error("refused");
      // siteLinked is a metadata-only fact for paste protection: true only when
      // this reply observed an actual login match for the document's origin.
      // A locked, disconnected or busy host stays "unknown" (null) so a paste
      // is never blocked on a guess.
      if (!capability || pending || pendingOTP || pendingPasskey)
        return { connected: !!capability, candidates: [], siteLinked: null };
      if (
        !core.sameContext(c, context) ||
        matchCategory !== category ||
        Date.now() - lastMatchAt > 3000
      ) {
        await match(category, c.frameId);
        lastMatchAt = Date.now();
      }
      await current(c);
      const session =
        category === "login" ? multiStepFor(c.tabId, c.origin) : null;
      let list = rows.map((r) => ({
        id: r.id,
        revision: r.revision,
        title: r.title,
        category: rowCategory(r),
        ...(r.subtitle ? { subtitle: r.subtitle } : {}),
      }));
      if (session) {
        const index = list.findIndex((row) => row.id === session.itemId);
        if (index > 0) list.unshift(list.splice(index, 1)[0]);
      }
      return {
        connected: !!capability,
        neverSaveForOrigin: neverSaveOrigins.includes(c.origin),
        suppressInline: neverSaveOrigins.includes(c.origin),
        preferredItemId: session?.itemId || "",
        preferredTitle: session?.title || "",
        step: session?.stepCompleted || "",
        candidates: list,
        siteLinked: category === "login" ? rows.length > 0 : null,
      };
    }
    if (
      [
        "inline-fill",
        "inline-save",
        "inline-update",
        "inline-otp",
        "inline-fill-identity",
        "inline-fill-card",
      ].includes(message.type)
    ) {
      if (!core.sameContext(context, c)) throw Error("refused");
      let category = "login";
      if (message.type === "inline-fill-identity") category = "identity";
      else if (message.type === "inline-fill-card") category = "credit_card";
      else if (message.type === "inline-fill")
        category = message.category ?? "login";
      if (!validCategory(category)) throw Error("refused");
      // The inline menu is the only page-side card entry; its nonce is bound
      // to the browser-verified sender frame/document, never a page claim.
      if (
        category === "credit_card" &&
        !consumeUserGesture(message.userGesture, c)
      )
        throw Error("refused");
      if (message.type === "inline-fill") {
        await fill(
          message.id,
          message.revision,
          category,
          category === "credit_card",
        );
      } else if (message.type === "inline-fill-identity") {
        await fill(message.id, message.revision, "identity");
      } else if (message.type === "inline-fill-card") {
        await fill(message.id, message.revision, "credit_card", true);
      } else if (message.type === "inline-otp") {
        await otp(message.id, message.revision);
      } else {
        if ((c.frameId || 0) !== 0) throw Error("refused");
        if (message.type === "inline-update")
          await save(message.id, message.revision);
        else await save();
      }
      return { status };
    }
    if (message.type === "passkey-conditional-open")
      return conditionalOpen(message, c);
    if (message.type === "passkey-conditional-select")
      return conditionalSelect(message, c);
    if (
      message.type !== "passkey" ||
      !["create", "get"].includes(message.operation) ||
      !/^[a-f0-9-]{36}$/.test(message.id || "") ||
      typeof message.options !== "string" ||
      message.options.length > 32768 ||
      !capability ||
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    if (message.operation === "create" ? !offerSavePasskeys : !offerUsePasskeys)
      throw Error("refused");
    const generation = epoch,
      intent = {
        ...c,
        pageID: message.id,
        create: message.operation === "create",
      };
    pendingPasskey = intent;
    status = "请在原生窗口确认 Passkey 操作";
    try {
      const result = await request(
        "passkey-" + message.operation,
        { ...fields(c), options: message.options },
        125000,
      );
      await current(c);
      if (generation !== epoch || pendingPasskey !== intent)
        throw Error("refused");
      const credential = JSON.parse(result.credential);
      if (intent.create) passkeyUnknown = false;
      status = "Passkey 已交付；请核实网站结果";
      return { credential };
    } catch (error) {
      if (intent.create && !error.knownRefusal) {
        passkeyUnknown = true;
        error.passkeyUnknown = true;
      }
      throw error;
    } finally {
      if (pendingPasskey === intent) {
        pendingPasskey = null;
        context = null;
        rows = [];
      }
    }
  }
  function composedStatus() {
    return (
      status +
      (otpUnknown && !status.includes(OTP_UNKNOWN)
        ? " · " + OTP_UNKNOWN
        : "") +
      (fillUnknown && !status.includes(FILL_UNKNOWN)
        ? " · " + FILL_UNKNOWN
        : "") +
      (passkeyUnknown && !status.includes(PASSKEY_UNKNOWN)
        ? " · " + PASSKEY_UNKNOWN
        : "")
    );
  }
  async function stateSnapshot() {
    const site = await activeSite();
    return {
      connected: !!capability,
      autoLogin,
      quickFill,
      loginOverrides,
      offerSavePasskeys,
      offerUsePasskeys,
      watchtowerHIBP,
      status: composedStatus(),
      candidates: rows.map(candidateView),
      pending: !!pending || !!pendingOTP || !!pendingPasskey,
      otpPending: !!pendingOTP,
      saveBlocked: unconfirmedSave,
      origin: context?.origin || "",
      site,
      attachmentsSupported: !!capability && core.attachmentCapability(hostCapabilities),
      passkeyManagementSupported: passkeyManagementSupported(),
      historySupported:
        !!capability && hostCapabilities.includes("history-v1"),
      checkoutFramesSupported: checkoutFramePolicy(),
      passkeyConditionalSupported: passkeyConditionalSupported === true,
      watchtower: watchtowerReport,
    };
  }
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (!contentSender(sender)) return false;
    fromContent(message, sender).then(respond, (error) =>
      respond(
        error.passkeyUnknown
          ? { error: "NotAllowedError" }
          : { fallback: true },
      ),
    );
    return true;
  });
  const ATTACHMENT_REQUESTS = new Set([
    "attachment-begin",
    "attachment-chunk",
    "attachment-commit",
    "attachment-cancel",
    "attachment-read",
    "attachment-remove",
  ]);
  const ATTACHMENT_RESPONSES = {
    "attachment-begin": "attachment-transfer",
    "attachment-chunk": "attachment-transfer",
    "attachment-commit": "attachment-saved",
    "attachment-cancel": "attachment-cancelled",
    "attachment-read": "attachment-data",
    "attachment-remove": "attachment-removed",
  };
  function attachmentRefusal() {
    const error = Error("refused");
    error.keepStatus = true;
    return error;
  }
  function attachmentMetadataView(meta) {
    const view = {
      id: meta.id,
      file_name: core.safeFileName(meta.file_name),
      size: meta.size,
      sha256: meta.sha256,
    };
    if (typeof meta.mime_type === "string" && meta.mime_type)
      view.mime_type = meta.mime_type;
    if (typeof meta.protected === "boolean") view.protected = meta.protected;
    return view;
  }
  function attachmentTransferView(response) {
    return {
      transfer_id: response.transfer_id,
      offset: response.offset,
      size: response.size,
      expires_in_seconds: response.expires_in_seconds,
    };
  }
  function attachmentUploadExpiry(expiresInSeconds) {
    const seconds = Number.isSafeInteger(expiresInSeconds) ? expiresInSeconds : 0;
    return (
      Date.now() +
      Math.max(1, Math.min(seconds, core.ATTACHMENT_TRANSFER_TTL_SECONDS)) * 1000
    );
  }
  // Upload metadata is bounded by the host TTL: an orphan left by a closed
  // popup or a pending begin can never block uploads forever.
  function liveAttachmentUpload() {
    if (attachmentUpload && attachmentUpload.expiresAt <= Date.now())
      attachmentUpload = null;
    return attachmentUpload;
  }
  function attachmentsSupported() {
    return !!capability && core.attachmentCapability(hostCapabilities);
  }
  function passkeyManagementSupported() {
    return !!capability && core.passkeyManagementCapability(hostCapabilities);
  }
  function refreshPasskeyConditionalSupport() {
    const previous = passkeyConditionalSupported;
    passkeyConditionalSupported =
      !!capability &&
      offerUsePasskeys === true &&
      core.conditionalPasskeyCapability(hostCapabilities);
    if (previous === true && passkeyConditionalSupported !== true)
      clearConditionalIntentsWithNotify();
  }
  function conditionalIntentKey(c) {
    return c.tabId + ":" + c.documentId;
  }
  // Conditional account metadata only ever lives in this worker and in the
  // isolated UI. When a waiting intent is invalidated we notify the owning
  // document with a bare id so the panel cannot outlive the vault state.
  function takeConditionalIntents(predicate) {
    const taken = [];
    for (const [key, intent] of conditionalIntents)
      if (!predicate || predicate(intent)) {
        taken.push(intent);
        conditionalIntents.delete(key);
      }
    return taken;
  }
  function notifyConditionalCancelled(intents) {
    if (!intents.length || typeof api.tabs?.sendMessage !== "function") return;
    for (const intent of intents) {
      if (!/^[a-f0-9-]{36}$/.test(intent.pageID || "")) continue;
      if (!Number.isSafeInteger(intent.tabId) || intent.tabId < 1) continue;
      const message = {
        type: "locklark:conditional-passkey-cancel",
        id: intent.pageID,
      };
      try {
        const sent = api.tabs.sendMessage(intent.tabId, message, {
          documentId: intent.documentId,
        });
        if (sent && typeof sent.catch === "function") sent.catch(() => {});
      } catch {
        try {
          const sent = api.tabs.sendMessage(intent.tabId, message);
          if (sent && typeof sent.catch === "function") sent.catch(() => {});
        } catch {}
      }
    }
  }
  function clearConditionalIntentsWithNotify(predicate) {
    notifyConditionalCancelled(takeConditionalIntents(predicate));
  }
  function clearConditionalIntentsForTab(tabId) {
    clearConditionalIntentsWithNotify((intent) => intent.tabId === tabId);
  }
  function storeConditionalIntent(intent) {
    const key = conditionalIntentKey(intent);
    conditionalIntents.delete(key);
    while (conditionalIntents.size >= CONDITIONAL_INTENT_LIMIT) {
      const oldest = conditionalIntents.keys().next();
      if (oldest.done) break;
      const evicted = conditionalIntents.get(oldest.value);
      conditionalIntents.delete(oldest.value);
      notifyConditionalCancelled(evicted ? [evicted] : []);
    }
    conditionalIntents.set(key, intent);
  }
  function conditionalOptionsValid(raw) {
    if (
      typeof raw !== "string" ||
      raw.length < 2 ||
      raw.length > CONDITIONAL_OPTIONS_MAX
    )
      return false;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return false;
    }
    return (
      !!parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      typeof parsed.challenge === "string" &&
      parsed.challenge.length > 0 &&
      parsed.challenge.length <= 1024
    );
  }
  function conditionalRequestOptions(raw, credentialID) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw Error("refused");
    }
    if (!credentialID) return raw;
    parsed.allowCredentials = [{ type: "public-key", id: credentialID }];
    return JSON.stringify(parsed);
  }
  function conditionalCandidateView(entry) {
    return {
      item_id: entry.item_id,
      revision: entry.revision,
      title: entry.title,
      credential_id: entry.credential_id,
      ...(core.validCredentialRevision(entry.credential_revision)
        ? { credential_revision: entry.credential_revision }
        : {}),
      rp_id: entry.rp_id,
      user_name: entry.user_name,
      display_name: entry.display_name,
    };
  }
  async function conditionalOpen(message, c) {
    await settingsReady;
    refreshPasskeyConditionalSupport();
    if (
      Object.keys(message).some(
        (key) => !["type", "id", "options"].includes(key),
      ) ||
      !/^[a-f0-9-]{36}$/.test(message.id || "") ||
      !conditionalOptionsValid(message.options) ||
      !passkeyConditionalSupported
    )
      throw Error("refused");
    const generation = epoch,
      intent = {
        ...c,
        pageID: message.id,
        options: message.options,
        capability,
        epoch: generation,
        credentials: [],
        truncated: false,
      };
    storeConditionalIntent(intent);
    let response;
    try {
      response = await request(
        "passkey-list",
        { ...fields(c), options: message.options },
        8000,
      );
    } catch (error) {
      if (conditionalIntents.get(conditionalIntentKey(c)) === intent)
        conditionalIntents.delete(conditionalIntentKey(c));
      throw error;
    }
    if (
      generation !== epoch ||
      !passkeyConditionalSupported ||
      intent.capability !== capability ||
      conditionalIntents.get(conditionalIntentKey(c)) !== intent ||
      !response ||
      response.type !== "passkey-candidates" ||
      !core.validConditionalPasskeyList(response.passkeys)
    )
      throw Error("refused");
    await current(c);
    if (conditionalIntents.get(conditionalIntentKey(c)) !== intent)
      throw Error("refused");
    intent.credentials = response.passkeys.map((entry) => ({
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
      ...(core.validCredentialRevision(entry.credential_revision)
        ? { credential_revision: entry.credential_revision }
        : {}),
    }));
    intent.truncated = response.truncated === true;
    // Public, metadata-only projection: the isolated UI receives exactly these
    // keys and nothing else from the native vault.
    return {
      passkeys: response.passkeys.map(conditionalCandidateView),
      truncated: intent.truncated,
    };
  }
  // A conditional intent only stays authoritative while this exact record is
  // still the one stored for the sender document, under the same epoch,
  // capability and advertised support. Every check is repeated after each
  // await because all of them can change while a probe is in flight.
  function conditionalSelectionBound(intent, message, c, key) {
    return (
      !!intent &&
      conditionalIntents.get(key) === intent &&
      intent.pageID === message.id &&
      intent.epoch === epoch &&
      intent.capability === capability &&
      passkeyConditionalSupported === true &&
      core.sameContext(intent, c)
    );
  }
  async function conditionalSelect(message, c) {
    await settingsReady;
    refreshPasskeyConditionalSupport();
    const key = conditionalIntentKey(c),
      intent = conditionalIntents.get(key),
      native = message.native === true,
      allowed = native
        ? ["type", "id", "native"]
        : [
            "type",
            "id",
            "item_id",
            "revision",
            "credential_id",
            "credential_revision",
          ],
      required = native
        ? ["type", "id", "native"]
        : ["type", "id", "item_id", "revision", "credential_id"];
    if (
      !required.every((field) => Object.hasOwn(message, field)) ||
      Object.keys(message).some((field) => !allowed.includes(field)) ||
      !conditionalSelectionBound(intent, message, c, key) ||
      // Listing candidates is read-only, but a selection claims the single
      // native approval slot. It must never displace an ordinary fill, OTP or
      // Passkey approval that is already in flight.
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    let candidate = null;
    if (native) {
      if (intent.truncated !== true) throw Error("refused");
    } else {
      if (
        !/^[a-f0-9]{32}$/.test(message.item_id || "") ||
        !/^[a-f0-9]{64}$/.test(message.revision || "") ||
        !core.validCredentialID(message.credential_id)
      )
        throw Error("refused");
      // One stored candidate must match the full public selector exactly: item,
      // parent revision, credential and (when the host supplies one) the exact
      // child revision. A missing, stale or borrowed selector is refused; no
      // first-parent or first-credential fallback exists.
      candidate =
        intent.credentials.find(
          (entry) =>
            entry.item_id === message.item_id &&
            entry.revision === message.revision &&
            entry.credential_id === message.credential_id,
        ) || null;
      if (!candidate) throw Error("refused");
      const storedChild = core.validCredentialRevision(candidate.credential_revision)
        ? candidate.credential_revision
        : "";
      if (storedChild) {
        if (message.credential_revision !== storedChild)
          throw Error("refused");
      } else {
        // Legacy host: no child revision exists, so it is only compatible
        // with a singleton item and a selection that does not invent one.
        if (Object.hasOwn(message, "credential_revision"))
          throw Error("refused");
        if (
          intent.credentials.filter((entry) => entry.item_id === candidate.item_id)
            .length !== 1
        )
          throw Error("refused");
      }
    }
    await current(c);
    // The probe yields control: this exact intent can be cancelled, replaced
    // or rebound, and an ordinary approval can start, while it is in flight.
    // Revalidate everything and claim the shared approval slot in one
    // synchronous step so a canceled or superseded selection never sends a
    // stale native get and never overwrites a newer intent.
    if (
      !conditionalSelectionBound(intent, message, c, key) ||
      pending ||
      pendingOTP ||
      pendingPasskey
    )
      throw Error("refused");
    const childRevision =
      candidate && core.validCredentialRevision(candidate.credential_revision)
        ? candidate.credential_revision
        : "";
    conditionalIntents.delete(key);
    const generation = epoch,
      options = conditionalRequestOptions(
        intent.options,
        native ? "" : message.credential_id,
      ),
      approval = { ...intent, create: false };
    pendingPasskey = approval;
    status = "请在原生窗口确认 Passkey 操作";
    try {
      const result = await request(
        "passkey-get",
        {
          ...fields(c),
          options,
          ...(native
            ? {}
            : {
                item_id: candidate.item_id,
                revision: candidate.revision,
                credential_id: candidate.credential_id,
                ...(childRevision
                  ? { credential_revision: childRevision }
                  : {}),
              }),
        },
        125000,
      );
      await current(c);
      // A late native reply must not escape an invalidation that happened
      // while the approval was pending: the approval slot, epoch, capability
      // and advertised support all still have to describe this approval.
      if (
        generation !== epoch ||
        pendingPasskey !== approval ||
        intent.capability !== capability ||
        passkeyConditionalSupported !== true
      )
        throw Error("refused");
      const credential = JSON.parse(result.credential);
      status = "Passkey 已交付；请核实网站结果";
      return { credential };
    } finally {
      if (pendingPasskey === approval) pendingPasskey = null;
    }
  }

  async function attachmentNative(type, fields) {
    if (!attachmentsSupported()) {
      status = "当前原生宿主不支持附件";
      throw attachmentRefusal();
    }
    const response = await request(type, { capability, ...fields }, 30000);
    if (
      !core.validResponse(response) ||
      response.type !== ATTACHMENT_RESPONSES[type]
    )
      throw attachmentRefusal();
    return response;
  }
  async function attachmentOperation(message) {
    if (!attachmentsSupported()) {
      status = "当前原生宿主不支持附件";
      throw attachmentRefusal();
    }
    const itemID = /^[a-f0-9]{32}$/.test(message.id || "");
    const revision = /^[a-f0-9]{64}$/.test(message.revision || "");
    switch (message.type) {
      case "attachment-begin": {
        const fileName = core.safeFileName(message.file_name);
        const size = message.size;
        if (
          !itemID ||
          !revision ||
          !fileName ||
          !Number.isSafeInteger(size) ||
          size < 0 ||
          size > core.ATTACHMENT_MAX_BYTES ||
          typeof message.sha256 !== "string" ||
          !/^[a-f0-9]{64}$/.test(message.sha256) ||
          (message.mime_type !== undefined && !core.validMimeType(message.mime_type))
        )
          throw attachmentRefusal();
        // Exactly one in-memory upload token per connection.
        if (liveAttachmentUpload()) throw attachmentRefusal();
        const response = await attachmentNative("attachment-begin", {
          item_id: message.id,
          revision: message.revision,
          file_name: fileName,
          size,
          sha256: message.sha256,
          ...(typeof message.mime_type === "string" && message.mime_type
            ? { mime_type: message.mime_type }
            : {}),
        });
        if (response.offset !== 0 || response.size !== size)
          throw attachmentRefusal();
        // A newer upload (or a cancel) may have claimed the slot while the
        // begin was in flight; never resurrect over it.
        if (liveAttachmentUpload()) throw attachmentRefusal();
        attachmentUpload = {
          itemId: message.id,
          revision: message.revision,
          transferId: response.transfer_id,
          offset: response.offset,
          size: response.size,
          expiresAt: attachmentUploadExpiry(response.expires_in_seconds),
        };
        return { attachmentTransfer: attachmentTransferView(response) };
      }
      case "attachment-chunk": {
        const active = liveAttachmentUpload();
        const bytes = core.base64Decode(message.data, core.ATTACHMENT_CHUNK_BYTES);
        if (
          !active ||
          message.transfer_id !== active.transferId ||
          !Number.isSafeInteger(message.offset) ||
          message.offset !== active.offset ||
          !bytes ||
          bytes.length < 1 ||
          bytes.length > core.ATTACHMENT_CHUNK_BYTES ||
          active.offset + bytes.length > active.size
        ) {
          if (bytes) bytes.fill(0);
          throw attachmentRefusal();
        }
        const length = bytes.length;
        let response;
        try {
          response = await attachmentNative("attachment-chunk", {
            transfer_id: active.transferId,
            offset: active.offset,
            data: message.data,
          });
        } catch (error) {
          if (attachmentUpload === active) attachmentUpload = null;
          throw error;
        } finally {
          bytes.fill(0);
        }
        // A cancel or a newer upload may have replaced the record while the
        // chunk was in flight; a late reply must not resurrect it.
        if (attachmentUpload !== active) throw attachmentRefusal();
        if (
          response.transfer_id !== active.transferId ||
          response.size !== active.size ||
          response.offset !== active.offset + length
        ) {
          attachmentUpload = null;
          throw attachmentRefusal();
        }
        attachmentUpload = {
          itemId: active.itemId,
          revision: active.revision,
          transferId: active.transferId,
          offset: response.offset,
          size: response.size,
          expiresAt: attachmentUploadExpiry(response.expires_in_seconds),
        };
        return { attachmentTransfer: attachmentTransferView(response) };
      }
      case "attachment-commit": {
        const active = liveAttachmentUpload();
        if (
          !active ||
          message.transfer_id !== active.transferId ||
          active.offset !== active.size
        )
          throw attachmentRefusal();
        let response;
        try {
          response = await attachmentNative("attachment-commit", {
            transfer_id: active.transferId,
          });
        } catch (error) {
          if (attachmentUpload === active) attachmentUpload = null;
          throw error;
        }
        if (attachmentUpload === active) attachmentUpload = null;
        if (
          response.item_id !== active.itemId ||
          !/^[a-f0-9]{64}$/.test(response.revision || "")
        )
          throw attachmentRefusal();
        vaultSearchGeneration++;
        detailCache.clear();
        vaultItems = [];
        status = "附件已保存";
        return {
          attachmentSaved: {
            item_id: response.item_id,
            revision: response.revision,
            attachment: attachmentMetadataView(response.attachment),
          },
        };
      }
      case "attachment-cancel": {
        if (!/^[a-f0-9]{32}$/.test(message.transfer_id || ""))
          throw attachmentRefusal();
        const active = liveAttachmentUpload();
        if (active && active.transferId === message.transfer_id)
          attachmentUpload = null;
        if (!active || message.transfer_id !== active.transferId)
          return { attachmentCancelled: { transfer_id: message.transfer_id } };
        const response = await attachmentNative("attachment-cancel", {
          transfer_id: active.transferId,
        });
        return { attachmentCancelled: { transfer_id: response.transfer_id } };
      }
      case "attachment-read": {
        if (
          !itemID ||
          !revision ||
          !core.validAttachmentID(message.attachment_id) ||
          !Number.isSafeInteger(message.offset) ||
          message.offset < 0 ||
          message.offset > core.ATTACHMENT_MAX_BYTES ||
          !Number.isSafeInteger(message.length) ||
          message.length < 1 ||
          message.length > core.ATTACHMENT_CHUNK_BYTES
        )
          throw attachmentRefusal();
        const response = await attachmentNative("attachment-read", {
          item_id: message.id,
          revision: message.revision,
          attachment_id: message.attachment_id,
          offset: message.offset,
          length: message.length,
        });
        if (
          response.item_id !== message.id ||
          response.revision !== message.revision ||
          response.attachment.id !== message.attachment_id ||
          response.offset !== message.offset
        )
          throw attachmentRefusal();
        const bytes = core.base64Decode(response.data, core.ATTACHMENT_CHUNK_BYTES);
        const length = bytes ? bytes.length : -1;
        if (bytes) bytes.fill(0);
        if (
          length < 0 ||
          length > message.length ||
          response.next_offset !== message.offset + length
        )
          throw attachmentRefusal();
        // The bytes go straight back to the popup; they never enter the
        // snapshot, detail cache, storage or logs.
        return {
          attachmentData: {
            item_id: response.item_id,
            revision: response.revision,
            attachment: attachmentMetadataView(response.attachment),
            offset: response.offset,
            next_offset: response.next_offset,
            done: response.done,
            data: response.data,
          },
        };
      }
      case "attachment-remove": {
        if (!itemID || !revision || !core.validAttachmentID(message.attachment_id))
          throw attachmentRefusal();
        const response = await attachmentNative("attachment-remove", {
          item_id: message.id,
          revision: message.revision,
          attachment_id: message.attachment_id,
        });
        if (
          response.item_id !== message.id ||
          response.attachment_id !== message.attachment_id ||
          !/^[a-f0-9]{64}$/.test(response.revision || "")
        )
          throw attachmentRefusal();
        vaultSearchGeneration++;
        detailCache.clear();
        vaultItems = [];
        status = "附件已删除";
        return {
          attachmentRemoved: {
            item_id: response.item_id,
            revision: response.revision,
            attachment_id: response.attachment_id,
          },
        };
      }
      default:
        throw attachmentRefusal();
    }
  }
  // Private popup runtime port. Only the extension's own popup page may open
  // it, and only the native host can make the capability available.
  api.runtime.onConnect?.addListener((port) => {
    if (port?.name === ROUTE_LIFECYCLE_PORT_NAME) {
      openRouteLifecyclePort(port, port?.sender).catch(() => {
        try {
          port.disconnect();
        } catch {}
      });
      return;
    }
    openClipboardPort(port, port?.sender);
  });
  // A route tab is admitted only by the browser's sender identity: the exact
  // extension page, its exact tab, its exact route URL and fragment. It can
  // then send only ROUTE_MESSAGE_TYPES to the route handlers below; it never
  // receives the ordinary popup state or actions.
  // Shared admission: the browser's sender identity must agree with a live
  // route's exact tab and URL. `sender.url` may lag within one tab, so only
  // its extension page prefix and frame are checked here; every claim, copy
  // or read below re-queries the tab and the source anchors afterwards.
  async function routeMessage(sender) {
    const tab = sender?.tab
      ? await routeTabAt(sender.tab.id, sender.tab.url)
      : null;
    const pageURL = routePageURL(sender, tab);
    const token = routeTokenFromPage(pageURL);
    const grant = token ? routeGrants.get(token) || null : null;
    if (
      !grant ||
      !routeLive(grant) ||
      sender.tab.id !== grant.tabId ||
      !(await routeAnchors(grant))
    ) {
      routeLifecycleDiag(
        !grant
          ? "fallback-no-grant"
          : !routeLive(grant)
            ? "fallback-not-live"
            : sender.tab.id !== grant.tabId
              ? "fallback-wrong-tab"
              : "fallback-anchor-mismatch",
      );
      revokeRoute(grant);
      throw Error("refused");
    }
    routeLifecycleDiag("fallback-accepted");
    return grant;
  }
  function validRouteRequest(message) {
    return (
      !!message &&
      typeof message === "object" &&
      !Array.isArray(message) &&
      typeof message.type === "string" &&
      ROUTE_MESSAGE_TYPES.has(message.type)
    );
  }
  async function routeRequest(message, sender) {
    if (!validRouteRequest(message)) throw Error("refused");
    const grant = await routeMessage(sender);
    requireRoute(grant);
    switch (message.type) {
      case "route-claim":
        return routeClaim(message, grant);
      case "route-close": {
        const closed = routeClose(message, grant);
        return closed || { type: "route-closed", token: grant.token };
      }
      case "route-copy-field": {
        const copy = await routeFieldValue(message, grant, true);
        return { copiedField: copy };
      }
      // The one approved read happens inside the claim. A route tab may not
      // spend a second native item-get, so this branch never starts one. The
      // ordinary action-popup item-get path is a different listener and is
      // unchanged.
      case "item-get":
        throw Error("refused");
      // The remaining allowed actions only exist in the action popup or need
      // a page to target. A route tab is never a fill target and keeps fill,
      // OTP and open-and-fill disabled in this checkpoint: fail closed.
      case "fill":
      case "otp":
      case "open-and-fill":
      case "copy-field":
      case "reveal-field":
        revokeRoute(grant);
        throw Error("refused");
      default:
        // No route message ever falls back to an approved-detail read.
        throw Error("refused");
    }
  }
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (core.validSender(sender, api.runtime)) return false;
    if (!sender?.tab || sender.id !== api.runtime.id) return false;
    if (!validRouteRequest(message)) {
      // Any other message from an extension tab of a live route is refused
      // and the route ends; unrelated extension pages are simply not ours.
      const pageURL =
        typeof sender.url === "string" && typeof sender.tab.url === "string"
          ? routeTokenFromPage(routePageURL(sender, sender.tab))
          : "";
      if (pageURL) revokeRoute(routeGrants.get(pageURL) || null);
      return false;
    }
    routeRequest(message, sender).then(
      (reply) => sendResponse(reply || { error: "refused" }),
      () => sendResponse({ error: "refused" }),
    );
    return true;
  });
  // The route tab reports its clamp in pagehide. That is a report, not a
  // trusted signal, but honouring it can only end this page's own route
  // early, and the sender identity and exact tab are still checked first.
  // It only revokes: it never triggers a read.
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (
      message?.type !== "route-close" ||
      core.validSender(sender, api.runtime) ||
      !sender?.tab ||
      sender.id !== api.runtime.id ||
      routePageURL(sender, sender.tab) === ""
    )
      return false;
    const token = routeTokenFromPage(sender.tab.url);
    const grant = routeGrants.get(token);
    if (grant && grant.tabId === sender.tab.id && message.token === token)
      revokeRoute(grant);
    sendResponse({ type: "route-closed" });
    return false;
  });
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!core.validSender(sender, api.runtime)) return false;
    if (!message || typeof message !== "object" || !ATTACHMENT_REQUESTS.has(message.type))
      return false;
    const requestEpoch = epoch;
    attachmentOperation(message).then(
      (payload) => sendResponse(payload),
      (error) => {
        if (!error?.keepStatus && requestEpoch === epoch)
          status = "附件操作被拒绝";
        sendResponse({
          error: "refused",
          status,
          attachmentsSupported: attachmentsSupported(),
        });
      },
    );
    return true;
  });
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!core.validSender(sender, api.runtime)) return false;
    if (message && typeof message === "object" && ATTACHMENT_REQUESTS.has(message.type))
      return false;
    const requestEpoch = epoch;
    const run = async () => {
      if (!message || typeof message !== "object") throw Error("refused");
      const extra = {};
      switch (message.type) {
        case "state":
          await settingsReady;
          break;
        case "diagnostics":
          if (Object.keys(message).sort().join(",") !== "type")
            throw Error("refused");
          await settingsReady;
          extra.diagnostics = await diagnosticsSnapshot();
          break;
        case "settings": {
          await settingsReady;
          const next = {
            ...settings,
            generatorDefaults: { ...settings.generatorDefaults },
            loginOverrides: { ...settings.loginOverrides },
            disabledInlineMenuOrigins: [
              ...settings.disabledInlineMenuOrigins,
            ],
            neverSaveOrigins: [...settings.neverSaveOrigins],
          };
          for (const key of [
            "autoLogin",
            "offerSavePasskeys",
            "offerUsePasskeys",
            "sharedDesktopSession",
            "allowBiometricUnlock",
            "showToolbarBadgeCount",
            "showInlineMenu",
            "openAndFillAutoSubmit",
            "offerFillIdentitiesAndCards",
            "offerSaveLogins",
            "showInlineGenerator",
            "watchtowerLocalChecks",
            "watchtowerHIBP",
          ])
            if (typeof message[key] === "boolean") next[key] = message[key];
          if (
            message.generatorDefaults &&
            typeof message.generatorDefaults === "object" &&
            !Array.isArray(message.generatorDefaults)
          )
            next.generatorDefaults = sanitizeGeneratorDefaults(
              message.generatorDefaults,
            );
          if (
            /^[a-f0-9]{32}$/.test(message.id || "") &&
            typeof message.enabled === "boolean"
          )
            next.loginOverrides[message.id] = message.enabled;
          if (["system", "light", "dark"].includes(message.theme))
            next.theme = message.theme;
          if (
            Number.isSafeInteger(message.clipboardClearSeconds) &&
            message.clipboardClearSeconds >= 5 &&
            message.clipboardClearSeconds <= 300
          )
            next.clipboardClearSeconds = message.clipboardClearSeconds;
          const normalized = core.normalizeSettings(next);
          await api.storage.local.set(normalized);
          applySettings(normalized);
          updateBadge();
          rebuildContextMenus();
          break;
        }
        case "clear-never-save-origin": {
          const info = await activeTabInfo();
          if (!info) throw Error("refused");
          neverSaveOrigins = neverSaveOrigins.filter(
            (origin) => origin !== info.origin,
          );
          await persistNeverOrigins();
          break;
        }
        case "connect":
          void connect();
          break;
        case "native-connect":
          if (Object.keys(message).sort().join(",") !== "type")
            throw Error("refused");
          void connect();
          extra.nativeConnect = { started: true };
          break;
        case "native-unlock": {
          if (Object.keys(message).sort().join(",") !== "type")
            throw Error("refused");
          if (!port) {
            void connect();
            extra.nativeUnlock = {
              ok: false,
              pending: true,
              status: "正在启动 Locklark，请在窗口中完成解锁",
            };
            break;
          }
          try {
            const reply = await request("unlock-request", {}, 8000);
            const unlocked = reply.unlocked === true;
            status = unlocked
              ? "Locklark 已解锁，请重新连接"
              : "请在 Locklark 窗口中完成解锁";
            extra.nativeUnlock = {
              ok: reply.type === "status",
              pending: false,
              unlocked,
              status,
            };
          } catch {
            status = "无法请求桌面解锁，请确认 Locklark 正在运行";
            extra.nativeUnlock = { ok: false, pending: false, status };
          }
          break;
        }
        case "disconnect":
          disconnectWithStatus("已断开");
          break;
        case "lock":
          lockVault();
          break;
        case "watchtower": {
          const keys = Object.keys(message).sort().join(",");
          if (keys !== "type" && keys !== "includeHibp,type")
            throw Error("refused");
          if (
            message.includeHibp !== undefined &&
            typeof message.includeHibp !== "boolean"
          )
            throw Error("refused");
          await runWatchtower(message);
          break;
        }
        case "watchtower-open":
          if (
            Object.keys(message).sort().join(",") !== "origin,type" ||
            typeof message.origin !== "string"
          )
            throw Error("refused");
          await openWatchtower(message.origin);
          break;
        case "commit-staged-save": {
          if (!/^[a-f0-9]{32}$/.test(message.stageId || ""))
            throw Error("refused");
          const c = await captureTopDocument();
          const result = await commitStagedSave(
            message.stageId,
            {
              mode: message.mode,
              itemId: message.itemId,
              revision: message.revision,
              title: message.title,
            },
            c,
          );
          return { ...result };
        }
        case "dismiss-staged-save":
        case "never-save-origin": {
          const c = await captureTopDocument();
          const stageId = /^[a-f0-9]{32}$/.test(message.stageId || "")
            ? message.stageId
            : "";
          const result = await dismissStaged(
            stageId,
            message.type === "never-save-origin" ||
              message.neverForOrigin === true,
            c,
          );
          return { ...result, status };
        }
        case "generate":
        case "popup-generate": {
          const generated = await generateResult(message);
          let historyId = generated.historyId || "";
          if (message.recordHistory === true) {
            const info = await activeTabInfo();
            historyId = recordGenerated(
              info?.origin || "",
              typeof message.username === "string" ? message.username : "",
              generated,
            );
          }
          return {
            password: generated.password,
            profile: generated.profile,
            historyId,
            generatedPassword: generated.password,
          };
        }
        case "generator-fill": {
          const c = await captureTopDocument();
          const result = await inlineGenerateFill(message, c, epoch);
          return { ...result, status };
        }
        case "generator-history-fill": {
          if (!/^[a-f0-9]{32}$/.test(message.historyId || ""))
            throw Error("refused");
          pruneGenerated();
          const c = await captureTopDocument();
          const entry = generatedHistory.find(
            (item) => item.id === message.historyId,
          );
          if (
            !entry ||
            entry.origin !== c.origin ||
            typeof entry.password !== "string" ||
            entry.password.length < 4 ||
            entry.password.length > 256 ||
            !entry.password.isWellFormed()
          )
            throw Error("refused");
          let fill = null;
          try {
            const results = await api.scripting.executeScript({
              target: { tabId: c.tabId, documentIds: [c.documentId] },
              func: core.fillGeneratedPassword,
              args: [c.origin, entry.password, Date.now() + 1500],
            });
            if (
              results.length === 1 &&
              results[0].frameId === 0 &&
              results[0].documentId === c.documentId &&
              results[0].result?.ok === true
            )
              fill = results[0].result;
          } catch {}
          const staged = await stageSave(
            {
              username: fill?.username || entry.username || "",
              password: entry.password,
              isNewPassword: true,
              isPasswordChange: fill?.isPasswordChange === true,
            },
            c,
          );
          return {
            password: entry.password,
            profile: entry.profile,
            historyId: entry.id,
            filledCount: fill?.filledCount || 0,
            stageId: staged.stageId || "",
            mode: staged.mode || "",
            status,
          };
        }
        case "generator-history-save": {
          if (!/^[a-f0-9]{32}$/.test(message.historyId || ""))
            throw Error("refused");
          pruneGenerated();
          const c = await captureTopDocument();
          const entry = generatedHistory.find(
            (item) => item.id === message.historyId,
          );
          if (
            !entry ||
            entry.origin !== c.origin ||
            typeof entry.password !== "string" ||
            entry.password.length < 4 ||
            entry.password.length > 256 ||
            !entry.password.isWellFormed()
          )
            throw Error("refused");
          const staged = await stageSave(
            {
              username: entry.username || "",
              password: entry.password,
              isNewPassword: true,
              isPasswordChange: false,
            },
            c,
          );
          return {
            password: entry.password,
            profile: entry.profile,
            historyId: entry.id,
            filledCount: 0,
            stageId: staged.stageId || "",
            mode: staged.mode || "",
            status: staged.stageId
              ? "已暂存生成密码，请确认保存"
              : status,
          };
        }
        case "match": {
          const category = message.category ?? "login";
          if (!validCategory(category)) throw Error("refused");
          await match(category);
          break;
        }
        case "save-new":
          void save().catch(() => {
            if (requestEpoch === epoch)
              status = unconfirmedSave ? SAVE_UNKNOWN : "未保存";
          });
          break;
        case "save-update":
          if (
            typeof message.id !== "string" ||
            typeof message.revision !== "string"
          )
            throw Error("refused");
          void save(message.id, message.revision).catch(() => {
            if (requestEpoch === epoch)
              status = unconfirmedSave ? SAVE_UNKNOWN : "未保存";
          });
          break;
        case "otp":
          if (
            Object.keys(message).sort().join(",") !== "id,revision,type" ||
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "")
          )
            throw Error("refused");
          void otp(message.id, message.revision).catch(() => {
            if (requestEpoch === epoch) status = "本次验证码填充被拒绝";
          });
          break;
        case "cancel-otp":
          if (Object.keys(message).join(",") !== "type") throw Error("refused");
          cancelOTP();
          break;
        case "checkout-frames":
          extra.checkoutPicker = await startCheckoutPicker(message);
          break;
        case "checkout-select":
          extra.checkoutStarted = await selectCheckout(message);
          break;
        case "checkout-cancel":
          await cancelCheckoutPickerMessage(message);
          break;
        case "item-save":
          await settingsReady;
          // Any vault mutation may change the reviewed card revision.
          clearCheckoutPicker();
          extra.saved = await saveVaultItem(message);
          break;
        case "add-site": {
          if (
            Object.keys(message).sort().join(",") !== "id,origin,revision,type"
          )
            throw Error("refused");
          extra.added = await addSiteToItem(message);
          break;
        }
        case "item-state":
          clearCheckoutPicker();
          extra.itemState = await setItemState(message);
          break;
        case "item-history": {
          if (!capability || !hostCapabilities.includes("history-v1"))
            throw Error("refused");
          if (Object.keys(message).sort().join(",") !== "id,revision,type")
            throw Error("refused");
          const response = await request(
            "item-history",
            {
              capability,
              item_id: message.id,
              revision: message.revision,
            },
            12000,
          );
          extra.history = {
            item_id: response.item_id,
            revision: response.revision,
            entries: publicHistory(response.entries),
          };
          break;
        }
        case "item-restore-history": {
          if (!capability || !hostCapabilities.includes("history-v1"))
            throw Error("refused");
          if (
            Object.keys(message).sort().join(",") !==
            "historyIndex,id,revision,type"
          )
            throw Error("refused");
          if (
            !Number.isInteger(message.historyIndex) ||
            message.historyIndex < 0 ||
            message.historyIndex > 19
          )
            throw Error("refused");
          const response = await request(
            "item-restore-history",
            {
              capability,
              item_id: message.id,
              revision: message.revision,
              history_index: message.historyIndex,
            },
            20000,
          );
          if (response.type !== "item-saved") throw Error("refused");
          detailCache.clear();
          vaultItems = [];
          vaultSearchGeneration++;
          status = "已恢复历史版本";
          extra.saved = {
            item_id: response.item_id,
            revision: response.revision,
          };
          break;
        }
        case "fill": {
          const category = message.category ?? "login";
          if (
            typeof message.id !== "string" ||
            typeof message.revision !== "string" ||
            !validCategory(category)
          )
            throw Error("refused");
          if (category === "credit_card") {
            // Bind the popup's nonce to the active tab and its top document
            // as the browser reports them now, never to a popup claim.
            const active = await captureTopDocument(0);
            if (!consumeUserGesture(message.userGesture, active))
              throw Error("refused");
          }
          void fill(
            message.id,
            message.revision,
            category,
            category === "credit_card",
          ).catch(() => {
            if (requestEpoch === epoch) status = "本次请求被拒绝";
          });
          break;
        }
        case "vault-search":
        case "vault-list": {
          await settingsReady;
          const result = await vaultSearch(
            message.query,
            message.category,
            message.passkeysOnly === true,
            message.stateFilter,
          );
          extra.vaultItems = result.items;
          extra.vaultSource = result.source;
          extra.vaultFallback = result.fallback;
          extra.vaultStale = result.stale === true;
          extra.passkeysUnsupported = result.unsupported === true;
          break;
        }
        case "passkey-remove": {
          const removeFields = Object.keys(message).sort().join(",");
          if (
            (removeFields !== "credential_id,id,revision,type" &&
              removeFields !==
                "credential_id,credential_revision,id,revision,type") ||
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "") ||
            !core.validCredentialID(message.credential_id) ||
            (message.credential_revision !== undefined &&
              !core.validCredentialRevision(message.credential_revision))
          )
            throw Error("refused");
          try {
            extra.passkeyRemoved = await removePasskey(message);
          } catch (error) {
            if (requestEpoch === epoch)
              status = error.uncertain
                ? "Passkey 删除结果未确认，请刷新核实"
                : error.keepStatus
                  ? status
                  : "Passkey 删除被拒绝";
            extra.passkeyRemoveError = error.uncertain ? "uncertain" : "refused";
          }
          break;
        }
        case "item-get":
          if (
            !/^[a-f0-9]{32}$/.test(message.id || "") ||
            !/^[a-f0-9]{64}$/.test(message.revision || "")
          )
            throw Error("refused");
          extra.detail = await getVaultItem(message.id, message.revision);
          break;
        // An ordinary vault click asks for the persistent route instead, so
        // its detail is never read from this transient action popup.
        case "open-route":
          pruneRoutes();
          extra.routeCreated = await createRoute(message, sender);
          break;
        case "copy-field":
          extra.copiedField = await copyFieldValue(message);
          break;
        case "reveal-field":
          extra.revealedField = await fieldValue(message, false);
          break;
        case "open-and-fill":
          extra.openAndFill = await openAndFill(message);
          break;
        case "site-settings":
          await setSiteSettings(
            typeof message.disabledInline === "boolean"
              ? message.disabledInline
              : typeof message.disabledInlineMenu === "boolean"
                ? message.disabledInlineMenu
                : undefined,
            typeof message.neverSave === "boolean"
              ? message.neverSave
              : undefined,
          );
          break;
        default:
          throw Error("refused");
      }
      return extra;
    };
    const respondState = async (extra = {}) => {
      let pendingSave = null;
      try {
        pendingSave = await activePendingSave();
      } catch {}
      sendResponse({
        ...statePayload({ ...extra, pendingSave }),
        ...snapshot(),
        ...(await stateSnapshot()),
        ...extra,
        pendingSave,
      });
    };
    run().then(respondState, () => {
      if (requestEpoch === epoch)
        status = unconfirmedSave
          ? SAVE_UNKNOWN
          : "操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面";
      return respondState();
    });
    return true;
  });
})();
