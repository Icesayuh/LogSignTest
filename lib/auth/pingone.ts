import type { Account, AccountStore, NewAccount } from "./accounts";
import { AccountStoreError, type StoreErrorField } from "./errors";

// PingOne Directory as the account database. Server-only: the worker app's client secret
// must never reach the browser, and this file is only imported from server actions.

export type Config = {
  apiUrl: string;
  authUrl: string;
  envId: string;
  clientId: string;
  clientSecret: string;
  populationId: string;
};

export function isPingOneConfigured(): boolean {
  return Boolean(process.env.PINGONE_ENV_ID);
}

// Where PingOne lives for this tenant. The two URL overrides exist for tests; normally the region is all you set.
function pingOneEndpoints(): { apiUrl: string; authUrl: string; envId: string } {
  const env = process.env;
  const region = env.PINGONE_REGION || "com";
  return {
    apiUrl: env.PINGONE_API_URL || `https://api.pingone.${region}`,
    authUrl: env.PINGONE_AUTH_URL || `https://auth.pingone.${region}`,
    envId: env.PINGONE_ENV_ID ?? "",
  };
}

export function readConfig(): Config {
  const env = process.env;
  const missing = ["PINGONE_ENV_ID", "PINGONE_CLIENT_ID", "PINGONE_CLIENT_SECRET", "PINGONE_POPULATION_ID"].filter(
    (name) => !env[name],
  );
  if (missing.length) {
    throw new Error(`PingOne is partly configured. Missing: ${missing.join(", ")}.`);
  }
  return {
    ...pingOneEndpoints(),
    envId: env.PINGONE_ENV_ID!,
    clientId: env.PINGONE_CLIENT_ID!,
    clientSecret: env.PINGONE_CLIENT_SECRET!,
    populationId: env.PINGONE_POPULATION_ID!,
  };
}

// ---- worker token (cached per server instance) ----
let cachedToken: { value: string; expiresAt: number } | null = null;

export async function workerToken(cfg: Config): Promise<string> {
  if (cachedToken && Date.now() < cachedToken.expiresAt - 30_000) return cachedToken.value;

  const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
  const res = await fetch(`${cfg.authUrl}/${cfg.envId}/as/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`PingOne token request failed (${res.status}). Check the worker app's client ID, secret and auth method.`);

  const data = (await res.json()) as { access_token: string; expires_in?: number };
  cachedToken = { value: data.access_token, expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000 };
  return cachedToken.value;
}

export type ApiResult = { status: number; ok: boolean; data: any };

// `auth: true` targets PingOne's authentication host (https://auth.pingone.<region>/<env>/...),
// which is where the MFA deviceAuthentications API lives; otherwise the Management API host.
export async function call(
  cfg: Config,
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: string; auth?: boolean } = {},
): Promise<ApiResult> {
  const token = await workerToken(cfg);
  const base = init.auth ? `${cfg.authUrl}/${cfg.envId}` : `${cfg.apiUrl}/v1/environments/${cfg.envId}`;
  const res = await fetch(`${base}${path}`, {
    method: init.method ?? "GET",
    headers: { Authorization: `Bearer ${token}`, ...init.headers },
    body: init.body,
    cache: "no-store",
  });
  if (res.status === 401) cachedToken = null; // token may have been revoked; fetch a fresh one next time
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    // empty body
  }
  return { status: res.status, ok: res.ok, data };
}

// ---- mapping ----
type PingOneUser = { id: string; username?: string; email?: string; createdAt?: string };

function toAccount(user: PingOneUser, fallbackUsername: string): Account {
  return {
    id: user.id,
    username: user.username ?? fallbackUsername,
    email: user.email ?? "",
    createdAt: user.createdAt ?? new Date().toISOString(),
  };
}

function escapeFilter(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

async function findUser(cfg: Config, attribute: "username" | "email", value: string): Promise<PingOneUser | null> {
  const filter = encodeURIComponent(`${attribute} eq "${escapeFilter(value)}"`);
  const r = await call(cfg, `/users?filter=${filter}&limit=1`);
  if (!r.ok) throw new Error(`PingOne user lookup failed (${r.status}). Does the worker app have the Identity Data Admin role?`);
  return r.data?._embedded?.users?.[0] ?? null;
}

export const pingOneAccountStore: AccountStore = {
  async findByUsername(username) {
    const cfg = readConfig();
    const user = await findUser(cfg, "username", username);
    return user ? toAccount(user, username) : null;
  },

  async findByEmail(email) {
    const cfg = readConfig();
    const user = await findUser(cfg, "email", email);
    return user ? toAccount(user, "") : null;
  },

  async create({ username, email, password }: NewAccount) {
    const cfg = readConfig();
    const r = await call(cfg, "/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        email,
        population: { id: cfg.populationId },
        password: { value: password },
      }),
    });

    if (r.status === 201) return toAccount({ email, ...r.data }, username);

    const details: { code?: string; target?: string; message?: string }[] = r.data?.details ?? [];
    const target = (d: { target?: string }) => (d.target ?? "").toLowerCase();

    const taken = details.find((d) => d.code === "UNIQUENESS_VIOLATION");
    if (taken) {
      const field: StoreErrorField = target(taken).includes("email") ? "email" : "username";
      throw new AccountStoreError(
        field === "email" ? "An account with this email already exists. Sign in instead." : "That username is taken. Try another one.",
        field,
      );
    }
    const weak = details.find((d) => target(d).includes("password") || (d.code ?? "").includes("PASSWORD"));
    if (weak) {
      throw new AccountStoreError(weak.message || "That password doesn't meet the password policy.", "password");
    }

    throw new Error(`PingOne could not create the user (${r.status} ${r.data?.code ?? ""}).`);
  },

  async verify(username, password) {
    const cfg = readConfig();
    const user = await findUser(cfg, "username", username);
    if (!user) return null;

    const r = await call(cfg, `/users/${encodeURIComponent(user.id)}/password`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.pingidentity.password.check+json" },
      body: JSON.stringify({ password }),
    });

    // Auth/permission/server problems are real errors, not "wrong password".
    if (r.status === 401 || r.status === 403 || r.status >= 500) {
      throw new Error(`PingOne password check failed (${r.status}). Does the worker app have permission dir:validate:userPassword?`);
    }
    // Only an explicit OK signs the user in. A wrong password, lockout, no password set,
    // expired or must-change state all count as a failed sign-in.
    if (!r.ok || r.data?.status !== "OK") return null;
    return toAccount(user, username);
  },
};
