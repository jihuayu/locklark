// Fixed native failure-report projection. The picker diagnostic is read from
// the already-sanitized Error property and re-cleaned here; no raw picker or
// Error detail is copied. The native subobject is reduced to the fixed public
// controls needed for the current failure location. A disk write is best-effort
// and cannot replace the emitted report or the original failure.
import { join } from "node:path";
import {
  CHECKOUT_PICKER_STATUSES,
  sanitizeDetailFillDiagnostic,
} from "./browser_checkout_acceptance.mjs";

// Exact product labels whose boolean control state may be projected. Unknown
// labels, dynamic labels, values, text, paths and any other native field are
// dropped rather than guessed safe.
const NATIVE_CONTROL_LABELS = Object.freeze([
  "金库文件",
  "主密码",
  "使用应急资料…",
  "Secret Key",
  "解锁",
  "新建登录",
  "确认连接此扩展",
  "连接并启用快捷填充",
  "拒绝连接",
  "批准本次填充",
  "拒绝本次填充",
  "批准填充验证码",
  "拒绝填充验证码",
  "立即锁定",
  "新登录标题",
  "批准保存登录",
  "拒绝保存登录",
  "批准更新登录",
  "拒绝更新登录",
  "批准删除 Passkey",
  "拒绝删除 Passkey",
  "批准本次操作",
  "拒绝本次操作",
  "批准本次字段披露",
  "拒绝本次字段披露",
  "批准本次附件操作",
  "批准本次跨源银行卡填充",
  "拒绝本次跨源银行卡填充",
  "批准本次敏感字段填充",
  "拒绝本次敏感字段填充",
  "仅批准本次 CLI 请求",
  "拒绝本次请求",
  "验证主密码",
  "验证 Secret Key",
]);

const CONTROL_FIELDS = Object.freeze(["present", "enabled", "showing"]);

const FALLBACK_REPORT = Object.freeze({
  reason: "native failure report unavailable",
  stage: "unavailable",
  native: Object.freeze({ available: false }),
});

function fallbackReport() {
  return {
    reason: FALLBACK_REPORT.reason,
    stage: FALLBACK_REPORT.stage,
    native: { available: false },
  };
}

function projectNative(native) {
  // A missing or explicitly null native record carries no native data and keeps
  // its existing shape. Any other malformed shape fails closed.
  if (native === undefined || native === null) return native;
  if (typeof native !== "object" || Array.isArray(native)) {
    return { available: false };
  }
  if (typeof native.available !== "boolean") {
    return { available: false };
  }
  const projected = { available: native.available };
  if (!native.available) return projected;
  const controls = native.controls;
  if (controls === null || typeof controls !== "object" || Array.isArray(controls)) {
    return { available: false };
  }
  const projectedControls = {};
  for (const label of NATIVE_CONTROL_LABELS) {
    const record = controls[label];
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      continue;
    }
    if (!CONTROL_FIELDS.every((field) => typeof record[field] === "boolean")) {
      continue;
    }
    projectedControls[label] = {
      present: record.present,
      enabled: record.enabled,
      showing: record.showing,
    };
  }
  projected.controls = projectedControls;
  projected.controlCount = Object.keys(projectedControls).length;
  return projected;
}

function projectReport(report) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    return fallbackReport();
  }
  const projected = {};
  for (const key of Object.keys(report)) {
    if (key === "native") continue;
    // Caller-owned picker/route/status fields are already sanitized. Copying
    // them here preserves their existing public shape; only native is reduced.
    projected[key] = report[key];
  }
  if (Object.prototype.hasOwnProperty.call(report, "native")) {
    projected.native = projectNative(report.native);
  }
  return projected;
}

export function pickerReportFields(error, eligible) {
  if (!eligible) return {};
  if (!CHECKOUT_PICKER_STATUSES.includes(error?.pickerStatus)) return {};
  return {
    pickerStatus: error.pickerStatus,
    pickerDiagnostic:
      sanitizeDetailFillDiagnostic(error?.pickerDiagnostic) ?? "unknown",
  };
}

export function recordNativeFailure(writeFile, report, diagnostics) {
  let json;
  try {
    const projected = projectReport(report);
    json = JSON.stringify(projected, null, 2) + "\n";
    try {
      console.error("Native browser diagnostic: " + JSON.stringify(projected));
    } catch {}
  } catch {
    const fallback = fallbackReport();
    json = JSON.stringify(fallback, null, 2) + "\n";
    try {
      console.error("Native browser diagnostic: " + JSON.stringify(fallback));
    } catch {}
  }
  // The actual private directory is intentionally never printed. The disk
  // write still targets it and remains best-effort, 0600, and unable to replace
  // the caller's original failure.
  try {
    console.error("Synthetic diagnostic directory: [private]");
  } catch {}
  try {
    writeFile(join(diagnostics, "failure.json"), json, { mode: 0o600 });
  } catch {}
  return json;
}
