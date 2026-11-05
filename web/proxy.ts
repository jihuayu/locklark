import { randomBytes } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
export function proxy(request: NextRequest) {
  const origin = process.env.LOCKLARK_WEB_ORIGIN;
  if (!origin || request.headers.get("host") !== new URL(origin).host)
    return new NextResponse("Forbidden", { status: 403 });
  const nonce = randomBytes(24).toString("base64");
  const policy = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
  const headers = new Headers(request.headers);
  headers.set("Content-Security-Policy", policy);
  headers.set("x-nonce", nonce);
  headers.delete("x-forwarded-host");
  headers.delete("forwarded");
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Cross-Origin-Resource-Policy", "same-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  return response;
}
export const config = { matcher: "/:path*" };
