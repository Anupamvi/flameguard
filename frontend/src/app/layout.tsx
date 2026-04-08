import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { connection } from "next/server";
import "./globals.css";
import { Providers } from "@/lib/providers";
import { Sidebar } from "@/components/layout/sidebar";

function deriveSiteUrl() {
  const explicitSiteUrl = process.env.NEXT_PUBLIC_SITE_URL;
  if (explicitSiteUrl) {
    return explicitSiteUrl;
  }

  const apiUrl = process.env.NEXT_PUBLIC_API_URL;
  if (apiUrl) {
    try {
      const parsed = new URL(apiUrl);
      parsed.pathname = parsed.pathname.replace(/\/api\/v1\/?$/, "") || "/";
      parsed.search = "";
      parsed.hash = "";
      return parsed.toString().replace(/\/$/, "");
    } catch {
      // Fall back to the local default when the API URL is not a valid absolute URL.
    }
  }

  return "http://localhost:3000";
}

const siteUrl = deriveSiteUrl();
const description = "LLM-powered network security configuration and log auditor with safer policy generation";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "FlameGuard",
    template: "%s | FlameGuard",
  },
  description,
  openGraph: {
    title: "FlameGuard",
    description,
    url: siteUrl,
    siteName: "FlameGuard",
    type: "website",
  },
  twitter: {
    card: "summary",
    title: "FlameGuard",
    description,
  },
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  await connection();

  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <a
          href="#main-content"
          className="sr-only fixed left-4 top-4 z-50 rounded-lg bg-white px-3 py-2 text-sm font-semibold text-slate-900 focus:not-sr-only focus:outline-none"
        >
          Skip to content
        </a>
        <Providers>
          <div className="flex min-h-screen bg-surface-900">
            <Sidebar />
            <main id="main-content" className="min-w-0 flex-1 px-4 pb-6 pt-20 sm:px-6 md:ml-56 md:px-8 md:py-8">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
