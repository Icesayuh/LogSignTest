import { createHash, createPrivateKey, createPublicKey, createSign, createVerify, type JsonWebKey, type KeyObject } from "node:crypto";

// PingOne Recognize (Keyless Web SDK), server side. Server-only: nothing here may reach the browser.
//
// The browser runs the face capture; the server decides what the result means:
//   1. It hands the SDK a username, an optional signed user-authorization token, and "transaction data"
//      (a one-time value) for this attempt.
//   2. When the SDK succeeds it returns a JWT signed by Keyless. The server verifies that JWT against the
//      tenant's published public keys and checks it carries this attempt's transaction data.
// Nothing in the browser is trusted on its own: a "success" event without a verified JWT signs nobody in.

export type RecognizeConfig = {
  customer: string;
  authenticationServiceUrl: string; // WebSocket/HTTPS endpoint the browser SDK talks to (the console's "Authentication Service URL")
  operationsServiceUrl: string; // where the tenant's public signing keys are published ("Operations Service URL")
};

const trimSlash = (url: string) => url.replace(/\/+$/, "");

// On when the tenant is configured; KEYLESS_ENABLED=false switches the face check off without removing the settings.
export function recognizeConfigured(): boolean {
  const env = process.env;
  return env.KEYLESS_ENABLED !== "false" && Boolean(env.KEYLESS_CUSTOMER_NAME && env.KEYLESS_AUTHENTICATION_SERVICE_URL);
}

export function readRecognizeConfig(): RecognizeConfig {
  const env = process.env;
  const missing = ["KEYLESS_CUSTOMER_NAME", "KEYLESS_AUTHENTICATION_SERVICE_URL", "KEYLESS_OPERATIONS_SERVICE_URL"].filter((name) => !env[name]);
  if (missing.length) throw new Error(`PingOne Recognize is partly configured. Missing: ${missing.join(", ")}.`);
  return {
    customer: env.KEYLESS_CUSTOMER_NAME!,
    authenticationServiceUrl: trimSlash(env.KEYLESS_AUTHENTICATION_SERVICE_URL!),
    operationsServiceUrl: trimSlash(env.KEYLESS_OPERATIONS_SERVICE_URL!),
  };
}

// The name Recognize knows this person by. The account id is stable and holds no personal data,
// unlike a username or email, which people can change or that may repeat.
export function recognizeUsername(accountId: string): string {
  return accountId;
}

const b64url = (value: string | Buffer) => Buffer.from(value).toString("base64url");

// ---- user authorization (optional) ----
//
// When Keyless enables "User Authorization" for the tenant (type RemoteJWKSet), the SDK must present a
// short-lived JWT, signed by this app, whose `sub` is the username. That stops a browser from running a
// session as a different user than the server meant. Set KEYLESS_USER_AUTH_PRIVATE_KEY (an RSA private key
// in PEM form) to turn it on; the matching public key is served at /.well-known/jwks.json for Keyless to fetch.

const USER_AUTH_LIFETIME_SECONDS = 5 * 60;

function userAuthKey(): { privateKey: KeyObject; jwk: JsonWebKey; kid: string } | null {
  const pem = process.env.KEYLESS_USER_AUTH_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!pem) return null;
  const privateKey = createPrivateKey(pem);
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  // RFC 7638 thumbprint, so the key id is derived and nobody has to keep one in sync.
  const kid = createHash("sha256").update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })).digest("base64url");
  return { privateKey, jwk, kid };
}

export function userAuthorizationJwks(): { keys: object[] } | null {
  const key = userAuthKey();
  return key ? { keys: [{ ...key.jwk, kid: key.kid, use: "sig", alg: "RS256" }] } : null;
}

// undefined when user authorization isn't configured: the SDK is then started without a token.
export function userAuthorizationToken(username: string): string | undefined {
  const key = userAuthKey();
  if (!key) return undefined;
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: key.kid }));
  const claims = b64url(JSON.stringify({ sub: username, aud: "authentication-service", iat: now, exp: now + USER_AUTH_LIFETIME_SECONDS }));
  const signature = createSign("RSA-SHA256").update(`${header}.${claims}`).sign(key.privateKey);
  return `${header}.${claims}.${b64url(signature)}`;
}

// ---- verifying the result ----

const JWKS_TTL_MS = 24 * 60 * 60 * 1000;
const JWKS_MIN_REFETCH_MS = 5 * 60 * 1000; // an unknown key id can't make us hammer Keyless
const CLOCK_SKEW_SECONDS = 60;

type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };
let jwksCache: { keys: Map<string, KeyObject>; fetchedAt: number; attemptedAt: number } = { keys: new Map(), fetchedAt: 0, attemptedAt: 0 };

async function refreshJwks(cfg: RecognizeConfig, force: boolean): Promise<void> {
  const now = Date.now();
  if (!force && now - jwksCache.fetchedAt < JWKS_TTL_MS) return;
  if (now - jwksCache.attemptedAt < JWKS_MIN_REFETCH_MS && jwksCache.keys.size > 0) return;
  jwksCache.attemptedAt = now;

  const res = await fetch(`${cfg.operationsServiceUrl}/customers/${encodeURIComponent(cfg.customer)}/.well-known/jwks.json`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Could not fetch the Recognize signing keys (${res.status}). Check KEYLESS_OPERATIONS_SERVICE_URL and KEYLESS_CUSTOMER_NAME.`);

  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = new Map<string, KeyObject>();
  for (const jwk of body.keys ?? []) {
    if (!jwk.kid || jwk.kty !== "RSA" || (jwk.use && jwk.use !== "sig") || (jwk.alg && jwk.alg !== "RS256")) continue;
    keys.set(jwk.kid, createPublicKey({ key: jwk, format: "jwk" }));
  }
  jwksCache = { keys, fetchedAt: now, attemptedAt: now };
}

async function signingKey(cfg: RecognizeConfig, kid: string): Promise<KeyObject | undefined> {
  await refreshJwks(cfg, false);
  if (!jwksCache.keys.has(kid)) await refreshJwks(cfg, true); // a rotation may have added it
  return jwksCache.keys.get(kid);
}

function decodePart(part: string): Record<string, unknown> {
  const value = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("not an object");
  return value as Record<string, unknown>;
}

export type RecognizeVerdict = { ok: true; claims: Record<string, unknown> } | { ok: false; reason: string };

// Does any claim hold exactly this transaction data? The claim is `td` in the Mobile SDK's JWTs; the Web SDK's
// documentation doesn't name it, so `KEYLESS_JWT_TD_CLAIM` can point at another one, and other claims are
// checked too (and reported in the log) rather than rejecting a valid result over a claim name.
function carriesTransactionData(claims: Record<string, unknown>, expected: string): boolean {
  const named = process.env.KEYLESS_JWT_TD_CLAIM || "td";
  if (claims[named] === expected) return true;
  const holder = Object.entries(claims).find(([, value]) => value === expected || (typeof value === "object" && JSON.stringify(value).includes(expected)));
  if (holder) console.warn(`Recognize JWT carried the transaction data in claim "${holder[0]}", not "${named}". Set KEYLESS_JWT_TD_CLAIM=${holder[0]}.`);
  return Boolean(holder);
}

// Checks the signature, the time window, the issuer (when KEYLESS_JWT_ISSUER is set) and that the JWT is
// for this attempt (`expectedTransactionData`), so a JWT from another session or an earlier try is no use.
export async function verifyRecognizeJwt(token: string, expectedTransactionData: string): Promise<RecognizeVerdict> {
  try {
    const cfg = readRecognizeConfig();
    const parts = token.split(".");
    if (parts.length !== 3) return { ok: false, reason: "malformed JWT" };
    const [headerPart, payloadPart, signaturePart] = parts;

    const header = decodePart(headerPart);
    if (header.alg !== "RS256" || typeof header.kid !== "string") return { ok: false, reason: `unexpected header (alg=${String(header.alg)})` };

    const key = await signingKey(cfg, header.kid);
    if (!key) return { ok: false, reason: `unknown signing key ${header.kid}` };

    const signed = createVerify("RSA-SHA256").update(`${headerPart}.${payloadPart}`).verify(key, Buffer.from(signaturePart, "base64url"));
    if (!signed) return { ok: false, reason: "bad signature" };

    const claims = decodePart(payloadPart);
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS < now) return { ok: false, reason: "expired" };
    if (typeof claims.iat === "number" && claims.iat - CLOCK_SKEW_SECONDS > now) return { ok: false, reason: "issued in the future" };

    const issuer = process.env.KEYLESS_JWT_ISSUER;
    if (issuer && claims.iss !== issuer) return { ok: false, reason: `unexpected issuer ${String(claims.iss)}` };

    if (!carriesTransactionData(claims, expectedTransactionData)) {
      return { ok: false, reason: `transaction data missing or different (claims present: ${Object.keys(claims).join(", ")})` };
    }
    return { ok: true, claims };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "verification failed" };
  }
}
