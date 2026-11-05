import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const COOKIE = "locklark_management";
const tokenPattern = /^[0-9a-f]{64}$/;
const hash = (s: string) => createHash("sha256").update(s).digest();
export type Session = { id: string; expires: number };

// This registry is local to one long-running Node process. It stores only
// hashes of web session IDs, never vault keys or directory reports.
export class SessionRegistry {
  private code: Buffer;
  private codeExpires: number;
  private used = false;
  private attempts = 0;
  private sessions = new Map<string, number>();
  constructor(
    code: string,
    private now: () => number = Date.now,
    issuedAt = now(),
  ) {
    if (
      !tokenPattern.test(code) ||
      !Number.isSafeInteger(issuedAt) ||
      issuedAt > now()
    )
      throw new Error("Invalid management startup configuration");
    this.code = hash(code);
    this.codeExpires = issuedAt + 5 * 60_000;
  }
  exchange(code: string): Session | null {
    if (this.used || this.now() >= this.codeExpires || this.attempts >= 12)
      return null;
    this.attempts++;
    if (!tokenPattern.test(code) || !timingSafeEqual(hash(code), this.code))
      return null;
    this.used = true;
    this.code.fill(0);
    const id = randomBytes(32).toString("hex");
    const expires = this.now() + 30 * 60_000;
    this.sessions.set(hash(id).toString("hex"), expires);
    return { id, expires };
  }
  verify(id: string | undefined): number | null {
    if (!id || !tokenPattern.test(id)) return null;
    const key = hash(id).toString("hex");
    const expires = this.sessions.get(key);
    if (!expires || this.now() >= expires) {
      this.sessions.delete(key);
      return null;
    }
    return expires;
  }
  revoke(id: string | undefined) {
    if (id && tokenPattern.test(id))
      this.sessions.delete(hash(id).toString("hex"));
  }
}
export function validRequest(
  headers: Headers,
  expectedOrigin: string,
  mutation: boolean,
): boolean {
  const expected = new URL(expectedOrigin);
  if (
    expected.hostname !== "127.0.0.1" ||
    expected.protocol !== "http:" ||
    headers.get("host") !== expected.host
  )
    return false;
  const origin = headers.get("origin");
  if (
    (mutation && origin !== expectedOrigin) ||
    (origin !== null && origin !== expectedOrigin)
  )
    return false;
  const site = headers.get("sec-fetch-site");
  return (
    site === null || site === "same-origin" || (!mutation && site === "none")
  );
}
export type Connection = Readonly<{ version: 1; url: string; token: string }>;
export function parseConnection(raw: string): Connection {
  if (raw.length > 4096) throw new Error("Invalid management connection");
  const c = JSON.parse(raw) as Record<string, unknown>;
  if (
    !c ||
    Object.keys(c).sort().join(",") !== "token,url,version" ||
    c.version !== 1 ||
    typeof c.url !== "string" ||
    typeof c.token !== "string" ||
    !tokenPattern.test(c.token)
  )
    throw new Error("Invalid management connection");
  const u = new URL(c.url);
  if (
    u.protocol !== "http:" ||
    u.hostname !== "127.0.0.1" ||
    !u.port ||
    u.origin !== c.url ||
    u.username ||
    u.password ||
    u.search ||
    u.hash
  )
    throw new Error("Invalid management connection");
  return Object.freeze({ version: 1, url: c.url, token: c.token });
}
export async function readCode(request: Request): Promise<string | null> {
  if (
    request.headers.get("content-type")?.split(";")[0].trim() !==
      "application/json" ||
    !request.body
  )
    return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const deadline = setTimeout(() => {
    void reader.cancel().catch(() => undefined);
  }, 2000);
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 512) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
      string,
      unknown
    >;
    return body &&
      Object.keys(body).length === 1 &&
      typeof body.code === "string"
      ? body.code
      : null;
  } catch {
    return null;
  } finally {
    clearTimeout(deadline);
    reader.releaseLock();
  }
}
