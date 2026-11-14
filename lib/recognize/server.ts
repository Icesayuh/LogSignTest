import { createPublicKey, createPrivateKey, createSign, randomBytes, verify as cryptoVerify, type JsonWebKey, type KeyObject } from "node:crypto";

// PingOne Recognize (Keyless) on the server. Server-only: the signing key never reaches the browser.
//
// Two jobs, both required by the Web SDK guides:
//  1. Issue the short-lived "user authorization" JWT the SDK sends with every enrollment/authentication
//     (sub = username, aud = authentication-service). Keyless fetches our public key from /.well-known/jwks.json.
//  2. Verify the JWT the SDK returns on success, backend-to-backend, against Keyless's published JWKS.

export type RecognizeConfig = {
  customerName: string;
  serviceUrl: string; // Keyless Authentication Service URL (the SDK's ws-url / service.url)
  operationUrl: string; // Operation Service URL for your region (where the tenant JWKS lives)
  signingKey: string; // PEM private key used to sign user-authorization tokens
  signingKid: string;
  issuer?: string; // when set, the result JWT's iss must match
};

const REQUIRED = ["RECOGNIZE_CUSTOMER_NAME", "RECOGNIZE_SERVICE_URL", "RECOGNIZE_OPERATION_URL", "RECOGNIZE_SIGNING_KEY"] as const;

// On when the Recognize settings are present; RECOGNIZE_ENABLED=false turns it off.
export function recognizeRequired(): boolean {
  return process.env.RECOGNIZE_ENABLED !== "false" && Boolean(process.env.RECOGNIZE_CUSTOMER_NAME);
}

export class RecognizeError extends Error {}

export function readRecognizeConfig(): RecognizeConfig {
  const env = process.env;
  const missing = REQUIRED.filter((name) => !env[name]);
  if (missing.length) throw new Error(`PingOne Recognize is partly configured. Missing: ${missing.join(", ")}.`);
  return {
    customerName: env.RECOGNIZE_CUSTOMER_NAME!,
    serviceUrl: env.RECOGNIZE_SERVICE_URL!,
    operationUrl: env.RECOGNIZE_OPERATION_URL!.replace(/\/+$/, ""),
    signingKey: env.RECOGNIZE_SIGNING_KEY!.replace(/\\n/g, "\n"),
    signingKid: env.RECOGNIZE_SIGNING_KID || "logsigntest-1",
    issuer: env.RECOGNIZE_ISSUER || undefined,
  };
}

const b64url = (input: Buffer | string) => Buffer.from(input).toString("base64url");

// ---- 1. user authorization token + our JWKS ----

export const USER_AUTHORIZATION_TTL_SECONDS = 5 * 60;

export function signUserAuthorization(username: string, cfg = readRecognizeConfig()): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: cfg.signingKid };
  const claims = { sub: username, aud: "authentication-service", iat: now, exp: now + USER_AUTHORIZATION_TTL_SECONDS };
  const body = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = createSign("RSA-SHA256").update(body).sign(createPrivateKey(cfg.signingKey));
  return `${body}.${b64url(signature)}`;
}

// The public half of the signing key, in the shape Keyless's "RemoteJWKSet" setting expects.
export function publishedJwks(cfg = readRecognizeConfig()): { keys: JsonWebKey[] } {
  const jwk = createPublicKey(createPrivateKey(cfg.signingKey)).export({ format: "jwk" });
  return { keys: [{ ...jwk, kid: cfg.signingKid, use: "sig", alg: "RS256" }] };
}

// A single-use value handed to the SDK as `transaction.data`, so the signed result belongs to this attempt.
export const newTransactionData = () => randomBytes(16).toString("base64url");

// ---- 2. verifying the result JWT ----

type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };
const JWKS_TTL_MS = 24 * 60 * 60 * 1000;
const JWKS_REFETCH_MIN_MS = 5 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 5 * 60;
const MAX_JWT_AGE_SECONDS = 15 * 60;

let jwksCache: { keys: Jwk[]; fetchedAt: number; url: string } | null = null;

async function fetchJwks(cfg: RecognizeConfig, force: boolean): Promise<Jwk[]> {
  const url = `${cfg.operationUrl}/customers/${encodeURIComponent(cfg.customerName)}/.well-known/jwks.json`;
  const fresh = jwksCache && jwksCache.url === url && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS;
  const throttled = jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_REFETCH_MIN_MS;
  if (jwksCache && jwksCache.url === url && (force ? throttled : fresh)) return jwksCache.keys;

  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Could not fetch the Recognize JWKS (${res.status}).`);
  const data = (await res.json()) as { keys?: Jwk[] };
  jwksCache = { keys: data.keys ?? [], fetchedAt: Date.now(), url };
  return jwksCache.keys;
}

async function findKey(cfg: RecognizeConfig, kid: string | undefined): Promise<Jwk | null> {
  const match = (keys: Jwk[]) => keys.find((k) => k.kid === kid && (!k.use || k.use === "sig")) ?? null;
  return match(await fetchJwks(cfg, false)) ?? match(await fetchJwks(cfg, true)); // unknown kid: one rate-limited refresh
}

function decodePart<T>(part: string): T {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as T;
}

export type RecognizeResult = { claims: Record<string, unknown> };

// Throws RecognizeError when the token is not a valid, fresh, Keyless-signed result.
export async function verifyRecognizeJwt(jwt: string, cfg = readRecognizeConfig()): Promise<RecognizeResult> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new RecognizeError("Malformed token.");
  const [h, p, s] = parts;

  let header: { alg?: string; kid?: string };
  let claims: Record<string, unknown>;
  try {
    header = decodePart(h);
    claims = decodePart(p);
  } catch {
    throw new RecognizeError("Malformed token.");
  }

  const algs: Record<string, { hash: string; ecdsa: boolean }> = { RS256: { hash: "sha256", ecdsa: false }, ES256: { hash: "sha256", ecdsa: true } };
  const alg = header.alg ? algs[header.alg] : undefined;
  if (!alg) throw new RecognizeError("Unsupported signing algorithm.");

  const jwk = await findKey(cfg, header.kid);
  if (!jwk || (jwk.alg && jwk.alg !== header.alg)) throw new RecognizeError("Unknown signing key.");

  let key: KeyObject;
  try {
    key = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new RecognizeError("Unusable signing key.");
  }
  const ok = cryptoVerify(alg.hash, Buffer.from(`${h}.${p}`), alg.ecdsa ? { key, dsaEncoding: "ieee-p1363" } : key, Buffer.from(s, "base64url"));
  if (!ok) throw new RecognizeError("Bad signature.");

  const now = Math.floor(Date.now() / 1000);
  const exp = typeof claims.exp === "number" ? claims.exp : undefined;
  const iat = typeof claims.iat === "number" ? claims.iat : undefined;
  if (exp === undefined || exp + CLOCK_SKEW_SECONDS < now) throw new RecognizeError("Token expired.");
  if (iat === undefined || iat - CLOCK_SKEW_SECONDS > now || now - iat > MAX_JWT_AGE_SECONDS) throw new RecognizeError("Token is not fresh.");
  if (cfg.issuer && claims.iss !== cfg.issuer) throw new RecognizeError("Unexpected issuer.");

  return { claims };
}
