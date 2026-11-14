// Public/persisted native failure report fields are fixed enums, booleans, or
// safe counts. Raw native windows, coordinates, click records, control labels,
// and filesystem paths remain local to the caller.
const POPUP_STATUSES = new Set([
  "saved",
  "no-candidates",
  "context-changed",
  "paired",
  "popup-unavailable",
  "unknown",
  "locked",
  "disconnected",
  "native-pending",
  "refused",
  "quick-filling",
  "candidates-listed",
  "vault-listed",
  "watchtower",
  "filled",
  "other",
]);

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function safeStage(value) {
  return typeof value === "string" &&
    /^[a-z0-9][a-z0-9:_-]{0,100}$/.test(value)
    ? value
    : "unknown";
}

function safeReason(value, allowed) {
  return allowed.has(value) ? value : "unclassified acceptance failure";
}

export function sanitizeNativeSnapshot(snapshot) {
  if (
    !snapshot ||
    typeof snapshot !== "object" ||
    snapshot.available !== true
  ) {
    return {
      available: false,
      clicks: 0,
      controls: 0,
      enabled: 0,
      showing: 0,
    };
  }
  if (
    Number.isSafeInteger(snapshot.controls) &&
    Number.isSafeInteger(snapshot.enabled) &&
    Number.isSafeInteger(snapshot.showing)
  ) {
    return {
      available: true,
      clicks: safeCount(snapshot.clicks),
      controls: safeCount(snapshot.controls),
      enabled: safeCount(snapshot.enabled),
      showing: safeCount(snapshot.showing),
    };
  }
  let controls = 0;
  let enabled = 0;
  let showing = 0;
  const snapshotControls =
    snapshot.controls && typeof snapshot.controls === "object"
      ? snapshot.controls
      : {};
  for (const entries of Object.values(snapshotControls)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      controls++;
      if (entry && entry.enabled === true) enabled++;
      if (entry && entry.showing === true) showing++;
    }
  }
  return {
    available: true,
    clicks: Array.isArray(snapshot.clicks) ? snapshot.clicks.length : 0,
    controls,
    enabled,
    showing,
  };
}

export function sanitizeFailureReport(source, safeReasons = []) {
  const report = source && typeof source === "object" ? source : {};
  const popup =
    report.popup && typeof report.popup === "object" ? report.popup : {};
  const allowedReasons = new Set(safeReasons);
  return {
    reason: safeReason(report.reason, allowedReasons),
    stage: safeStage(report.stage),
    popup: {
      available: popup.available === true,
      status: POPUP_STATUSES.has(popup.status) ? popup.status : "unknown",
      refreshDisabled: popup.refreshDisabled === true,
      candidates: safeCount(popup.candidates),
    },
    native: sanitizeNativeSnapshot(report.native),
  };
}
