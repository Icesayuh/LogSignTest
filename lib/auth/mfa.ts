import { cookies } from "next/headers";
import type { Account } from "./accounts";
import { seal, unseal } from "./crypto";
import { beginMfa, chooseDevice, MFA_TTL_MS, submitOtp, type FlowResult, type MfaTransaction } from "./mfa-flow";
import type { MfaView } from "./mfa-types";

// Remembers, between the password step and the code step, that this browser already passed the
// password check. The cookie is sealed with AUTH_SECRET, so it can't be forged or edited, and it
// expires with the MFA window. PingOne's own device-authentication ID rides along inside it.

const MFA_COOKIE = "acp_mfa";

export type MfaOutcome = { done: true; account: Account } | { done: false; view: MfaView };

async function save(transaction: MfaTransaction | null): Promise<void> {
  const jar = await cookies();
  if (!transaction) {
    jar.delete(MFA_COOKIE);
    return;
  }
  jar.set(MFA_COOKIE, seal(transaction), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: MFA_TTL_MS / 1000,
  });
}

async function load(): Promise<MfaTransaction | null> {
  const jar = await cookies();
  const tx = unseal<MfaTransaction>(jar.get(MFA_COOKIE)?.value);
  return tx && tx.expiresAt > Date.now() ? tx : null;
}

async function settle(result: FlowResult): Promise<MfaOutcome> {
  await save(result.done ? null : result.transaction);
  return result.done ? { done: true, account: result.account } : { done: false, view: result.view };
}

const TIMED_OUT: MfaOutcome = { done: false, view: { step: "expired", error: "Your sign-in timed out. Start again." } };

export async function startMfa(account: Account): Promise<MfaOutcome> {
  return settle(await beginMfa(account));
}

export async function selectMfaDevice(deviceId: string): Promise<MfaOutcome> {
  const tx = await load();
  return tx ? settle(await chooseDevice(tx, deviceId)) : TIMED_OUT;
}

export async function verifyMfaCode(code: string): Promise<MfaOutcome> {
  const tx = await load();
  return tx ? settle(await submitOtp(tx, code)) : TIMED_OUT;
}

export async function cancelMfa(): Promise<void> {
  await save(null);
}
