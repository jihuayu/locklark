import { NextResponse, type NextRequest } from "next/server";
import { COOKIE, readCode, validRequest } from "../../../lib/security";
import { runtime } from "../../../lib/server";
export const dynamic = "force-dynamic";
export async function POST(request: NextRequest) {
  const state = runtime();
  if (!validRequest(request.headers, state.origin, true))
    return NextResponse.json({ error: "连接请求被拒绝" }, { status: 403 });
  const code = await readCode(request);
  const session = code ? state.registry.exchange(code) : null;
  if (!session)
    return NextResponse.json(
      { error: "连接码无效、已使用或已过期，请重新启动管理界面。" },
      { status: 401 },
    );
  const response = NextResponse.json({
    connected: true,
    expires: session.expires,
  });
  response.cookies.set(COOKIE, session.id, {
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    path: "/",
    maxAge: 1800,
  });
  return response;
}
export async function DELETE(request: NextRequest) {
  const state = runtime();
  if (!validRequest(request.headers, state.origin, true))
    return NextResponse.json({ error: "请求被拒绝" }, { status: 403 });
  state.registry.revoke(request.cookies.get(COOKIE)?.value);
  const response = NextResponse.json({ connected: false });
  response.cookies.set(COOKIE, "", {
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    path: "/",
    maxAge: 0,
  });
  return response;
}
