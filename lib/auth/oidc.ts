import { createHash, randomBytes } from "node:crypto";
import { seal, unseal } from "./crypto";
import { pingOneEndpoints } from "./pingone";

// Hosted sign-in through the PingOne "Login Web App" (OIDC authorization code flow + PKCE).
// PingOne shows the login page and runs the sign-on policy, which is where MFA happens.
// Server-only: the web app's client secret must never reach the browser.

export const OIDC_COOKIE = "acp_oidc";
export const OIDC_COOKIE_MAX_AGE_SECONDS = 60 * 10;

export class OidcError extends Error {}

export function isOidcConfigured(): boolean {
  return Boolean(process.env.PINGONE_OIDC_CLIENT_ID);
}

function readConfig() {
  const missing = ["PINGONE_ENV_ID", "PINGONE_OIDC_CLIENT_ID", "PINGONE_OIDC_CLIENT_SECRET"].filter((name) => !process.env[name]);
  if (missing.length) throw new OidcError(`PingOne sign-in is partly configured. Missing: ${missing.join(", ")}.`);
  return {
    ...pingOneEndpoints(),
    clientId: process.env.PINGONE_OIDC_CLIENT_ID!,
    clientSecret: process.env.PINGONE_OIDC_CLIENT_SECRET!,
  };
}

// APP_URL pins the redirect URI to exactly what is registered in PingOne; without it the
// address the browser used is taken, which is fine for localhost.
export function appOrigin(requestOrigin: string): string {
  return (process.env.APP_URL || requestOrigin).replace(/\/+$/, "");
}

export function redirectUri(requestOrigin: string): string {
  return `${appOrigin(requestOrigin)}/auth/callback`;
}

type Transaction = { state: string; nonce: string; verifier: string; expiresAt: number };

const randomToken = () => randomBytes(32).toString("base64url");

export function beginAuthorization(requestOrigin: string, loginHint?: string): { url: string; sealedTransaction: string } {
  const cfg = readConfig();
  const tx: Transaction = {
    state: randomToken(),
    nonce: randomToken(),
    verifier: randomToken(),
    expiresAt: Date.now() + OIDC_COOKIE_MAX_AGE_SECONDS * 1000,
  };

  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: redirectUri(requestOrigin),
    scope: "openid",
    state: tx.state,
    nonce: tx.nonce,
    code_challenge: createHash("sha256").update(tx.verifier).digest("base64url"),
    code_challenge_method: "S256",
    // Always ask for credentials (and so the sign-on policy, MFA included) instead of
    // silently reusing a PingOne session left over from a previous sign-in.
    prompt: "login",
  });
  if (loginHint) params.set("login_hint", loginHint);

  return { url: `${cfg.authUrl}/${cfg.envId}/as/authorize?${params}`, sealedTransaction: seal(tx) };
}

type IdTokenClaims = { sub?: string; aud?: string | string[]; nonce?: string; exp?: number };

function readIdToken(idToken: string): IdTokenClaims {
  const payload = idToken.split(".")[1];
  if (!payload) throw new OidcError("PingOne returned a malformed ID token.");
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as IdTokenClaims;
}

// Trades the one-time code for tokens and returns who signed in. The ID token arrives straight
// from PingOne's token endpoint over TLS, so (per OIDC Core 3.1.3.7) its signature need not be
// re-verified; the audience, nonce and expiry are checked here.
export async function completeAuthorization(
  requestOrigin: string,
  params: { code: string; state: string },
  sealedTransaction: string | undefined,
): Promise<{ userId: string }> {
  const cfg = readConfig();

  const tx = unseal<Transaction>(sealedTransaction);
  if (!tx || tx.expiresAt < Date.now()) throw new OidcError("The sign-in attempt expired. Start again.");
  if (tx.state !== params.state) throw new OidcError("Sign-in state did not match.");

  const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
  const res = await fetch(`${cfg.authUrl}/${cfg.envId}/as/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: redirectUri(requestOrigin),
      code_verifier: tx.verifier,
    }),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new OidcError(`PingOne token exchange failed (${res.status}). Check the web app's client secret, auth method and redirect URI.`);
  }

  const { id_token: idToken } = (await res.json()) as { id_token?: string };
  if (!idToken) throw new OidcError("PingOne did not return an ID token. Is the openid scope enabled on the web app?");

  const claims = readIdToken(idToken);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(cfg.clientId)) throw new OidcError("The ID token was issued for a different app.");
  if (claims.nonce !== tx.nonce) throw new OidcError("The ID token nonce did not match.");
  if (!claims.exp || claims.exp * 1000 < Date.now()) throw new OidcError("The ID token has expired.");
  if (!claims.sub) throw new OidcError("The ID token has no subject.");

  return { userId: claims.sub };
}
