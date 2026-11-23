import { randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import type { Account } from "./accounts";
import { seal, unseal } from "./crypto";
import type { MfaView } from "./mfa-types";
import { readRecognizeConfig, recognizeConfigured, recognizeUsername, userAuthorizationToken, verifyRecognizeJwt } from "./recognize";
import { isEnrolled, markEnrolled } from "./recognize-store";

// The face step that comes after the password and any verification code. Like the MFA step (mfa.ts),
// the server remembers in a sealed cookie that this browser got this far, so nothing in the page can skip
// it: the session only starts in continueRecognize, after Keyless's signed result checks out.

const COOKIE = "acp_rcg";
const TTL_MS = 10 * 60 * 1000;

type Mode = "enroll" | "auth";
type Transaction = { account: Account; mode: Mode; transactionData: string; expiresAt: number };

export type RecognizeAction = { type: "result"; jwt: string } | { type: "retry" };
export type RecognizeOutcome = { done: true; account: Account } | { done: false; view: MfaView };

export function recognizeRequired(): boolean {
  return recognizeConfigured();
}

async function save(tx: Transaction | null): Promise<void> {
  const jar = await cookies();
  if (!tx) {
    jar.delete(COOKIE);
    return;
  }
  jar.set(COOKIE, seal(tx), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: TTL_MS / 1000,
  });
}

async function load(): Promise<Transaction | null> {
  const jar = await cookies();
  const tx = unseal<Transaction>(jar.get(COOKIE)?.value);
  return tx && tx.expiresAt > Date.now() ? tx : null;
}

const PROMPT: Record<Mode, string> = {
  enroll: "Register your face to finish setting up. You'll use it to sign in from now on.",
  auth: "Look at your camera to confirm it's you.",
};

// One attempt: fresh transaction data (and token), remembered here and handed to the page.
async function issue(account: Account, mode: Mode, error?: string): Promise<RecognizeOutcome> {
  const cfg = readRecognizeConfig();
  const username = recognizeUsername(account.id);
  const transactionData = `${mode}:${randomBytes(16).toString("hex")}`;
  await save({ account, mode, transactionData, expiresAt: Date.now() + TTL_MS });
  return {
    done: false,
    view: {
      step: "face",
      prompt: PROMPT[mode],
      error,
      face: {
        mode,
        customer: cfg.customer,
        username,
        serviceUrl: cfg.authenticationServiceUrl,
        transactionData,
        authorizationToken: userAuthorizationToken(username),
      },
    },
  };
}

// Call once the password (and MFA) succeeded. Someone with no face on record registers one here, in the same
// sign-in, so a registration that was abandoned halfway doesn't lock the account out.
export async function beginRecognize(account: Account): Promise<RecognizeOutcome> {
  return issue(account, (await isEnrolled(account)) ? "auth" : "enroll");
}

export async function continueRecognize(action: RecognizeAction): Promise<RecognizeOutcome> {
  const tx = await load();
  if (!tx) return { done: false, view: { step: "expired", error: "Your sign-in timed out. Start again." } };

  if (action.type === "retry") return issue(tx.account, tx.mode);

  const verdict = await verifyRecognizeJwt(action.jwt, tx.transactionData);
  if (!verdict.ok) {
    console.error(`Recognize result rejected (${tx.mode}): ${verdict.reason}`);
    return issue(tx.account, tx.mode, "We couldn't confirm that face scan. Try again.");
  }

  if (tx.mode === "enroll") {
    try {
      await markEnrolled(tx.account);
    } catch (error) {
      // The face is registered with Recognize; failing the sign-in would not undo that. Say loudly what to fix.
      console.error("Face registered, but it could not be recorded for next time:", error);
    }
  }
  await save(null);
  return { done: true, account: tx.account };
}

export async function cancelRecognize(): Promise<void> {
  await save(null);
}
