import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
const path = process.env.LOCKLARK_MANAGEMENT_CONNECTION;
const port = Number(process.env.PORT ?? 3417);
if (!path || !Number.isInteger(port) || port < 1024 || port > 65535) {
  console.error(
    "Set LOCKLARK_MANAGEMENT_CONNECTION to the private connection file.",
  );
  process.exit(1);
}
try {
  // Reuse the native reader on every platform: mode bits alone cannot validate
  // Windows ACLs or the integrity of the connection file's parent directories.
  const connectionPath = resolve(path);
  const executable = process.env.LOCKLARK_MANAGEMENT_EXECUTABLE;
  const raw = execFileSync(
    executable || process.env.LOCKLARK_GO || "go",
    executable
      ? ["--read-connection", connectionPath]
      : ["run", "./cmd/locklark-management", "--read-connection", connectionPath],
    {
      cwd: resolve(".."),
      encoding: "utf8",
      timeout: 60_000,
      maxBuffer: 4096,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const config = JSON.parse(raw);
  const url = new URL(config.url);
  if (
    config.version !== 1 ||
    url.hostname !== "127.0.0.1" ||
    url.protocol !== "http:" ||
    url.origin !== config.url ||
    !/^[0-9a-f]{64}$/.test(config.token)
  )
    throw new Error("invalid configuration");
  const code = randomBytes(32).toString("hex");
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(
    process.execPath,
    [
      resolve("node_modules/next/dist/bin/next"),
      "start",
      "--hostname",
      "127.0.0.1",
      "--port",
      String(port),
    ],
    {
      stdio: "inherit",
      env: {
        ...process.env,
        NODE_ENV: "production",
        NEXT_TELEMETRY_DISABLED: "1",
        LOCKLARK_CONNECTION_JSON: raw,
        LOCKLARK_WEB_CODE: code,
        LOCKLARK_WEB_ORIGIN: origin,
        LOCKLARK_WEB_STARTED_AT: String(Date.now()),
      },
    },
  );
  console.log(`管理界面：${origin}\n一次性连接码（5 分钟内有效）：${code}`);
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => child.kill(signal));
  child.on("exit", (status) => {
    process.exitCode = status ?? 1;
  });
} catch {
  console.error("Cannot read the private management connection configuration.");
  process.exitCode = 1;
}
