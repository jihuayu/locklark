// Owned setup primitives. Listen failures reject the setup promise, and only
// paths created under the synthetic acceptance prefix are removed.
import {
  closeSync,
  fstatSync,
  lstatSync,
  rmSync,
  writeSync,
} from "node:fs";

const OWNED_STATE_PREFIX = "/tmp/locklark-browser-acceptance-";
const HANDOFF_FD = "LOCKLARK_TEST_DIAGNOSTIC_FD";
const HANDOFF_LIMIT = 4096;

export function listenLoopback(server, port = 0) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    try {
      server.listen(port, "127.0.0.1");
    } catch (error) {
      server.off("error", onError);
      server.off("listening", onListening);
      reject(error);
    }
  });
}

export function cleanupOwnedState(state) {
  if (
    typeof state === "string" &&
    state.startsWith(OWNED_STATE_PREFIX)
  ) {
    rmSync(state, { recursive: true, force: true });
  }
}

export function writeDiagnosticHandoff(state) {
  const fd = Number(process.env[HANDOFF_FD]);
  if (!Number.isSafeInteger(fd) || fd < 3) return false;
  try {
    const pipe = fstatSync(fd);
    if (!pipe.isFIFO()) return false;
    if (
      typeof state !== "string" ||
      !state.startsWith(OWNED_STATE_PREFIX)
    ) {
      return false;
    }
    const info = lstatSync(state);
    if (!info.isDirectory() || info.isSymbolicLink()) return false;
    if (
      typeof process.getuid === "function" &&
      info.uid !== process.getuid()
    ) {
      return false;
    }
    const payload = state + "\n";
    if (Buffer.byteLength(payload, "utf8") > HANDOFF_LIMIT) return false;
    writeSync(fd, payload);
    closeSync(fd);
    return true;
  } catch {
    try {
      closeSync(fd);
    } catch {}
    return false;
  }
}
