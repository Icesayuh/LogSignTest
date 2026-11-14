import { cookies } from "next/headers";
import type { Account } from "@/lib/auth/accounts";
import { seal, unseal } from "@/lib/auth/crypto";
import { newTransactionData, readRecognizeConfig, signUserAuthorization, verifyRecognizeJwt } from "./server";
import type { RecognizeMode, RecognizeView } from "./types";

// Remembers, between the password step and the face step, which account passed the password check and
// which attempt (transaction data) the SDK was started for. Sealed with AUTH_SECRET like the MFA cookie.

const RECOGNIZE_COOKIE = "acp_recognize";
const RECOGNIZE_TTL_MS = 10 * 60 * 1000;

type Pending = { account: Account; mode: RecognizeMode; newAccount: boolean; transactionData: string; expiresAt: number };

async function save(pending: Pending | null): Promise<void> {
  const jar = await cookies();
  if (!pending) {
    jar.delete(RECOGNIZE_COOKIE);
    return;
  }
  jar.set(RECOGNIZE_COOKIE, seal(pending), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: RECOGNIZE_TTL_MS / 1000,
  });
}

async function load(): Promise<Pending | null> {
  const jar = await cookies();
  const pending = unseal<Pending>(jar.get(RECOGNIZE_COOKIE)?.value);
  return pending && pending.expiresAt > Date.now() ? pending : null;
}

function viewOf(pending: Pending): RecognizeView {
  const cfg = readRecognizeConfig();
  return {
    mode: pending.mode,
    username: pending.account.username,
    customer: cfg.customerName,
    serviceUrl: cfg.serviceUrl,
    authorizationToken: signUserAuthorization(pending.account.username, cfg),
    transactionData: pending.transactionData,
  };
}

// Password accepted (sign-in) or account created (register): start the face step.
export async function beginRecognize(account: Account, mode: RecognizeMode, newAccount = false): Promise<RecognizeView> {
  const pending: Pending = { account, mode, newAccount, transactionData: newTransactionData(), expiresAt: Date.now() + RECOGNIZE_TTL_MS };
  await save(pending);
  return viewOf(pending);
}

// A face-login that can't work (never enrolled) falls back to enrolling, still behind the password check.
export async function switchRecognizeMode(mode: RecognizeMode): Promise<RecognizeView | null> {
  const pending = await load();
  if (!pending) return null;
  const next: Pending = { ...pending, mode, transactionData: newTransactionData() };
  await save(next);
  return viewOf(next);
}

export type RecognizeCheck = { ok: true; account: Account; newAccount: boolean } | { ok: false; expired: boolean };

// The SDK reported success; check its signed JWT with Keyless before trusting it.
export async function completeRecognize(jwt: string): Promise<RecognizeCheck> {
  const pending = await load();
  if (!pending) return { ok: false, expired: true };
  try {
    await verifyRecognizeJwt(jwt);
  } catch (error) {
    console.error("Recognize JWT rejected:", error);
    return { ok: false, expired: false };
  }
  await save(null);
  return { ok: true, account: pending.account, newAccount: pending.newAccount };
}

export async function cancelRecognize(): Promise<void> {
  await save(null);
}
