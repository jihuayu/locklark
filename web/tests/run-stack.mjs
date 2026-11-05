import { spawn, execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile, mkdtemp, access } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
const state = await mkdtemp(join(tmpdir(), "locklark-web-test-"));
const root = resolve("..");
const go = process.env.LOCKLARK_GO || "go";
const env = { ...process.env, GOTOOLCHAIN: "go1.27.3" };
const binary = join(
  state,
  process.platform === "win32" ? "management.exe" : "management",
);
execFileSync(go, ["build", "-o", binary, "./cmd/locklark-management"], {
  cwd: root,
  env,
  stdio: "inherit",
});
execFileSync(go, ["run", "./web/tests/fixture", "-out", state], {
  cwd: root,
  env,
  stdio: "inherit",
});
const children = [];
function startBroker() {
  const child = spawn(
    binary,
    [
      "--directory",
      join(state, "team.db"),
      "--config",
      join(state, "config.json"),
      "--connection",
      join(state, "connection.json"),
    ],
    { stdio: ["ignore", "pipe", "inherit"] },
  );
  children.push(child);
  return child;
}
let broker = startBroker();
let stopped = false;
function stop() {
  if (stopped) return;
  stopped = true;
  for (const child of children) child.kill("SIGINT");
}
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, stop);
process.on("exit", stop);
async function waitForConnection() {
  for (let i = 0; ; i++) {
    try {
      await access(join(state, "connection.json"));
      break;
    } catch {
      if (i > 100 || broker.exitCode !== null)
        throw new Error("Test broker did not start");
      await new Promise((r) => setTimeout(r, 50));
    }
  }
}
await waitForConnection();
if (process.platform !== "win32") {
  for (const signal of ["SIGTERM", "SIGINT"]) {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("Broker shutdown timed out")),
        5000,
      );
      broker.once("exit", (code) => {
        clearTimeout(timer);
        code === 0
          ? resolve()
          : reject(new Error("Broker did not exit cleanly"));
      });
      broker.kill(signal);
    });
    let exists = true;
    try {
      await access(join(state, "connection.json"));
    } catch {
      exists = false;
    }
    if (exists)
      throw new Error("Broker left its connection credential after shutdown");
    broker = startBroker();
    await waitForConnection();
  }
}
await mkdir(".test-state", { recursive: true, mode: 0o700 });
const web = spawn(process.execPath, ["scripts/serve.mjs"], {
  env: {
    ...process.env,
    PORT: "3417",
    LOCKLARK_MANAGEMENT_CONNECTION: join(state, "connection.json"),
  },
  stdio: ["ignore", "pipe", "inherit"],
});
children.push(web);
let output = "",
  saved = false;
web.stdout.on("data", async (chunk) => {
  output += chunk.toString();
  const match = output.match(/一次性连接码（5 分钟内有效）：([a-f0-9]{64})/);
  if (match && !saved) {
    saved = true;
    await writeFile(
      ".test-state/access.json",
      JSON.stringify({
        code: match[1],
        connection: JSON.parse(
          await readFile(join(state, "connection.json"), "utf8"),
        ),
        directory: join(state, "team.db"),
      }),
      { mode: 0o600 },
    );
  }
  // Do not copy the generated management code into test output.
});
web.on("exit", (code) => {
  stop();
  process.exitCode = code ?? 1;
});
broker.on("exit", () => {
  if (!stopped) {
    stop();
    process.exitCode = 1;
  }
});
