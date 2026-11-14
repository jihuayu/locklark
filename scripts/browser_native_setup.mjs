// Owned setup primitives. Listen failures reject the setup promise, and only
// paths created under the synthetic acceptance prefix are removed.
import { rmSync } from "node:fs";

const OWNED_STATE_PREFIX = "/tmp/locklark-browser-acceptance-";

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
