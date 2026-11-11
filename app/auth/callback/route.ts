import { NextResponse, type NextRequest } from "next/server";
import { appOrigin, completeAuthorization, OIDC_COOKIE } from "@/lib/auth/oidc";
import { getPingOneAccountById } from "@/lib/auth/pingone";
import { startSession } from "@/lib/auth/session";

export const dynamic = "force-dynamic";

// PingOne sends the browser back here after the login page and MFA step.
export async function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  const params = request.nextUrl.searchParams;

  const finish = (path: string) => {
    const response = NextResponse.redirect(new URL(path, appOrigin(origin)));
    response.cookies.set(OIDC_COOKIE, "", { path: "/auth", maxAge: 0 }); // the attempt is over either way
    return response;
  };

  const providerError = params.get("error");
  if (providerError) {
    console.error("PingOne returned an error:", providerError, params.get("error_description"));
    return finish(providerError === "access_denied" ? "/?error=denied" : "/?error=signin_failed");
  }

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) return finish("/?error=signin_failed");

  try {
    const { userId } = await completeAuthorization(origin, { code, state }, request.cookies.get(OIDC_COOKIE)?.value);
    await startSession(await getPingOneAccountById(userId));
    return finish("/account");
  } catch (error) {
    console.error("PingOne sign-in failed:", error);
    return finish("/?error=signin_failed");
  }
}
