import { NextResponse, type NextRequest } from "next/server";
import { appOrigin, beginAuthorization, isOidcConfigured, OIDC_COOKIE, OIDC_COOKIE_MAX_AGE_SECONDS } from "@/lib/auth/oidc";

export const dynamic = "force-dynamic";

// Starts the hosted PingOne sign-in: remembers the PKCE/state values in a short-lived sealed
// cookie, then sends the browser to PingOne, which runs the login page and the MFA policy.
export async function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  const home = (query = "") => NextResponse.redirect(new URL(`/${query}`, appOrigin(origin)));

  if (!isOidcConfigured()) return home();

  try {
    // After registering, the username is passed along so PingOne's login page can pre-fill it.
    const hint = request.nextUrl.searchParams.get("hint")?.slice(0, 100) || undefined;
    const { url, sealedTransaction } = beginAuthorization(origin, hint);

    const response = NextResponse.redirect(url);
    response.cookies.set(OIDC_COOKIE, sealedTransaction, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax", // PingOne sends the browser back with a top-level GET, which Lax allows
      path: "/auth",
      maxAge: OIDC_COOKIE_MAX_AGE_SECONDS,
    });
    return response;
  } catch (error) {
    console.error("Could not start PingOne sign-in:", error);
    return home("?error=signin_failed");
  }
}
