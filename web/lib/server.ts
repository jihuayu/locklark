import "server-only";
import { request } from "node:http";
import { cookies } from "next/headers";
import { COOKIE, parseConnection, SessionRegistry } from "./security";
import { parseSummary, type Summary } from "./summary";

type Runtime = {
  registry: SessionRegistry;
  connection: ReturnType<typeof parseConnection>;
  origin: string;
};
const scope = globalThis as typeof globalThis & {
  __locklarkManagementRuntime?: Runtime;
};
export function runtime(): Runtime {
  if (!scope.__locklarkManagementRuntime) {
    const origin = process.env.LOCKLARK_WEB_ORIGIN ?? "";
    const url = new URL(origin);
    if (
      url.protocol !== "http:" ||
      url.hostname !== "127.0.0.1" ||
      !url.port ||
      url.origin !== origin
    )
      throw new Error("Management runtime unavailable");
    scope.__locklarkManagementRuntime = {
      registry: new SessionRegistry(
        process.env.LOCKLARK_WEB_CODE ?? "",
        Date.now,
        Number(process.env.LOCKLARK_WEB_STARTED_AT),
      ),
      connection: parseConnection(process.env.LOCKLARK_CONNECTION_JSON ?? ""),
      origin,
    };
    delete process.env.LOCKLARK_WEB_CODE;
    delete process.env.LOCKLARK_CONNECTION_JSON;
  }
  return scope.__locklarkManagementRuntime;
}
export async function sessionExpiry(): Promise<number | null> {
  return runtime().registry.verify((await cookies()).get(COOKIE)?.value);
}
export async function readSummary(): Promise<Summary> {
  const { connection } = runtime();
  const target = new URL(connection.url);
  // node:http makes a direct loopback connection; environment HTTP proxies,
  // redirects, Next fetch caching and arbitrary URLs cannot intercept the token.
  return new Promise((resolve, reject) => {
    const fail = () => reject(new Error("Management state unavailable"));
    const req = request(
      {
        hostname: "127.0.0.1",
        port: target.port,
        path: "/v1/summary",
        method: "GET",
        agent: false,
        headers: { Authorization: `Bearer ${connection.token}` },
      },
      (response) => {
        if (
          response.statusCode !== 200 ||
          response.headers["content-type"] !== "application/json"
        ) {
          response.destroy();
          fail();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 65536) {
            response.destroy();
            fail();
          } else chunks.push(chunk);
        });
        response.on("end", () => {
          try {
            resolve(
              parseSummary(JSON.parse(Buffer.concat(chunks).toString("utf8"))),
            );
          } catch {
            fail();
          }
        });
        response.on("error", fail);
        response.on("aborted", fail);
      },
    );
    const deadline = setTimeout(() => {
      req.destroy();
      fail();
    }, 4000);
    req.on("close", () => clearTimeout(deadline));
    req.on("error", fail);
    req.end();
  });
}
