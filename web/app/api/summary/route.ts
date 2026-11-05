import { NextResponse, type NextRequest } from "next/server";
import { COOKIE, validRequest } from "../../../lib/security";
import { readSummary, runtime } from "../../../lib/server";
export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  const state = runtime();
  if (
    !validRequest(request.headers, state.origin, false) ||
    request.nextUrl.search
  )
    return NextResponse.json({ error: "请求被拒绝" }, { status: 403 });
  if (!state.registry.verify(request.cookies.get(COOKIE)?.value))
    return NextResponse.json(
      { error: "管理会话已结束，请重新连接。" },
      { status: 401 },
    );
  try {
    return NextResponse.json(await readSummary());
  } catch {
    return NextResponse.json(
      { error: "无法验证当前本地目录，请检查管理服务。" },
      { status: 503 },
    );
  }
}
