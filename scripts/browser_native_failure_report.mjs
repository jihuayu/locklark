// Fixed native failure-report projection. The picker diagnostic is read from
// the already-sanitized Error property and re-cleaned here; no raw picker or
// Error detail is copied. A disk write is best-effort and cannot replace the
// emitted report or the original failure.
import { join } from "node:path";
import {
  CHECKOUT_PICKER_STATUSES,
  sanitizeDetailFillDiagnostic,
} from "./browser_checkout_acceptance.mjs";

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
  const json = JSON.stringify(report, null, 2) + "\n";
  console.error("Native browser diagnostic: " + JSON.stringify(report));
  console.error("Synthetic diagnostic directory: " + diagnostics);
  try {
    writeFile(join(diagnostics, "failure.json"), json, { mode: 0o600 });
  } catch {}
  return json;
}
