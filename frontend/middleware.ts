import { NextRequest, NextResponse } from "next/server";

// Cheap edge gate: if the access cookie is missing on a protected path,
// redirect to /login *before* React even renders. The page tree's own
// useAuth guard remains the authoritative check.
const PROTECTED_PREFIXES = [
  "/home",
  "/dashboard",
  "/scans",
  "/vuln-scans",
  "/targets",
  "/reports",
  "/settings",
  "/admin",
  "/verified-targets",
];

const PUBLIC_PATHS = ["/login", "/accept-invite"];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }
  if (!PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }
  const access = req.cookies.get("rt_access");
  if (!access) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
