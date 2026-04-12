import { NextRequest, NextResponse } from "next/server";

const ACCESS_COOKIE = "st_access_token";

const PROTECTED_PREFIXES = [
  "/dashboard",
  "/alerts",
  "/assets",
  "/investigations",
  "/activity",
  "/detections",
];

const AUTH_PAGES = ["/login"];

function isProtectedPath(pathname: string) {
  return PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

function isAuthPage(pathname: string) {
  return AUTH_PAGES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const accessToken = request.cookies.get(ACCESS_COOKIE)?.value;

  if (isProtectedPath(pathname) && !accessToken) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(loginUrl);
  }

  if (isAuthPage(pathname) && accessToken) {
    const nextParam = request.nextUrl.searchParams.get("next");
    const target = nextParam && nextParam.startsWith("/") ? nextParam : "/dashboard";
    return NextResponse.redirect(new URL(target, request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/alerts/:path*",
    "/assets/:path*",
    "/investigations/:path*",
    "/activity/:path*",
    "/detections/:path*",
    "/login/:path*",
  ],
};
