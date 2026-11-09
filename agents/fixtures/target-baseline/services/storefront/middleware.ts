// 授權檢查放在 middleware：自架（next start）時是 CVE-2025-29927 的利用前提之一。
import { NextResponse, type NextRequest } from "next/server";

export function middleware(req: NextRequest) {
  const session = req.cookies.get("brand_admin_session");
  if (!session) {
    return NextResponse.redirect(new URL("/login", req.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ["/admin/:path*"] };
