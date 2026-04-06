import { NextRequest, NextResponse } from "next/server";

function buildConnectSrc(): string {
  const sources = new Set(["'self'"]);

  const candidates = [process.env.NEXT_PUBLIC_API_URL];

  if (process.env.NODE_ENV !== "production") {
    candidates.push("http://localhost:8000/api/v1");
  }

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }

    try {
      sources.add(new URL(candidate).origin);
    } catch {
      // Ignore malformed URLs and keep the policy usable.
    }
  }

  return Array.from(sources).join(" ");
}

function buildContentSecurityPolicy(nonce: string): string {
  const isDev = process.env.NODE_ENV !== "production";

  return [
    "default-src 'self'",
    `connect-src ${buildConnectSrc()}`,
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self'",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' ${isDev ? "'unsafe-inline'" : `'nonce-${nonce}'`}`,
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ]
    .join("; ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const contentSecurityPolicy = buildContentSecurityPolicy(nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", contentSecurityPolicy);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  response.headers.set("Content-Security-Policy", contentSecurityPolicy);

  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};