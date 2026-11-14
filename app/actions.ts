"use server";

import { redirect } from "next/navigation";
import { accountStore as accounts } from "@/lib/auth/store";
import { AccountStoreError } from "@/lib/auth/errors";
import type { Account } from "@/lib/auth/accounts";
import { cancelMfa, continueMfa, startMfa, type MfaOutcome } from "@/lib/auth/mfa";
import { MfaFlowError, mfaRequired, type MfaAction } from "@/lib/auth/mfa-flow";
import type { MfaView } from "@/lib/auth/mfa-types";
import { beginRecognize, cancelRecognize, completeRecognize, switchRecognizeMode } from "@/lib/recognize/flow";
import { recognizeRequired } from "@/lib/recognize/server";
import type { RecognizeView } from "@/lib/recognize/types";
import { endSession, startSession } from "@/lib/auth/session";
import {
  hasErrors,
  normalizeEmail,
  normalizeUsername,
  validateRegistration,
  validateSignIn,
  type FieldErrors,
} from "@/lib/auth/validation";

export type AuthFormState = {
  fieldErrors: FieldErrors;
  formError?: string;
  values: { username: string; email: string };
  // Set once the password was accepted and a verification code is the next step.
  mfa?: MfaView;
  // Set when PingOne Recognize comes first: face enrollment after registering, face authentication after the password.
  recognize?: RecognizeView;
};

const ACCOUNT_HOME = "/account";

function readText(formData: FormData, field: string): string {
  const value = formData.get(field);
  return typeof value === "string" ? value : "";
}

// The password (or registration) just succeeded. Start the MFA step, or finish signing in when MFA is off.
async function continueToMfa(account: Account, values: AuthFormState["values"], newAccount = false): Promise<AuthFormState> {
  if (!mfaRequired()) {
    await startSession(account);
    redirect(ACCOUNT_HOME);
  }

  let outcome: MfaOutcome;
  try {
    outcome = await startMfa(account, { newAccount });
  } catch (error) {
    console.error("Could not start MFA:", error);
    const formError =
      error instanceof MfaFlowError ? error.message : "We couldn't start verification right now. Try again in a moment.";
    return { fieldErrors: {}, formError, values };
  }

  if (outcome.done) {
    await startSession(outcome.account);
    redirect(ACCOUNT_HOME);
  }
  return { fieldErrors: {}, values, mfa: outcome.view };
}

// The password (or registration) succeeded. When Recognize is on, the face step comes before MFA.
async function continueToFace(account: Account, values: AuthFormState["values"], newAccount: boolean): Promise<AuthFormState> {
  if (!recognizeRequired()) return continueToMfa(account, values, newAccount);
  try {
    return { fieldErrors: {}, values, recognize: await beginRecognize(account, newAccount ? "enroll" : "auth", newAccount) };
  } catch (error) {
    console.error("Could not start PingOne Recognize:", error);
    return { fieldErrors: {}, formError: "We couldn't start face verification right now. Try again in a moment.", values };
  }
}

export async function signIn(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  const username = normalizeUsername(readText(formData, "username"));
  const password = readText(formData, "password");
  const values = { username, email: "" };

  const fieldErrors = validateSignIn(username, password);
  if (hasErrors(fieldErrors)) return { fieldErrors, values };

  let account: Account | null;
  try {
    account = await accounts.verify(username, password);
  } catch (error) {
    console.error("Sign-in failed:", error);
    return { fieldErrors: {}, formError: "We can't reach the sign-in service right now. Try again in a moment.", values };
  }
  // One message for both cases so the form doesn't reveal which usernames are registered.
  if (!account) return { fieldErrors: {}, formError: "Wrong username or password. Try again, or create an account.", values };

  return continueToFace(account, values, false);
}

export async function register(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  const username = normalizeUsername(readText(formData, "username"));
  const email = normalizeEmail(readText(formData, "email"));
  const password = readText(formData, "password");
  const confirmPassword = readText(formData, "confirmPassword");
  const values = { username, email };

  const fieldErrors = validateRegistration(username, email, password, confirmPassword);
  if (hasErrors(fieldErrors)) return { fieldErrors, values };

  let account: Account;
  try {
    if (await accounts.findByUsername(username)) {
      return { fieldErrors: { username: "That username is taken. Try another one." }, values };
    }
    // Emails may repeat on purpose: people sign in by username, so only the username must be unique.
    account = await accounts.create({ username, email, password });
  } catch (error) {
    // The directory can reject a registration the form couldn't predict (password policy, a race on a username).
    if (error instanceof AccountStoreError && error.field) {
      return { fieldErrors: { [error.field]: error.message }, values };
    }
    console.error("Registration failed:", error);
    return { fieldErrors: {}, formError: "We couldn't create your account right now. Try again in a moment.", values };
  }

  // A new account enrolls its face first; after that it has no MFA method yet, so it lands on choosing one to set up.
  return continueToFace(account, values, true);
}

// Each MFA screen posts different fields, which says what the person just did.
function readMfaAction(formData: FormData): MfaAction {
  if (formData.has("deviceId")) return { type: "select", deviceId: readText(formData, "deviceId") };
  if (formData.has("back")) return { type: "back" };
  if (formData.has("credential")) return { type: "passkey", credential: readText(formData, "credential"), origin: readText(formData, "origin") };
  if (formData.has("skip")) return { type: "skip" };
  if (formData.has("method")) return { type: "method", method: readText(formData, "method") };
  if (formData.has("phone")) return { type: "phone", phone: readText(formData, "phone") };
  return { type: "verify", code: readText(formData, "otp") };
}

// Everything after the password: choosing a device or method, entering a phone number, entering a code.
export async function mfaStep(previous: MfaView, formData: FormData): Promise<MfaView> {
  let outcome: MfaOutcome;
  try {
    outcome = await continueMfa(readMfaAction(formData));
  } catch (error) {
    console.error("MFA step failed:", error);
    return { ...previous, error: "We can't reach the verification service right now. Try again in a moment." };
  }

  if (outcome.done) {
    await startSession(outcome.account);
    redirect(ACCOUNT_HOME);
  }
  return outcome.view;
}

export type RecognizeStepResult =
  | { kind: "mfa"; mfa: MfaView }
  | { kind: "switched"; view: RecognizeView }
  | { kind: "error"; message: string } // stay on the face step and let the person retry
  | { kind: "expired"; message: string }; // the attempt is gone; back to the form

// The face step reports back here: either the SDK's signed JWT (checked with Keyless), or a request to enroll instead.
export async function recognizeStep(formData: FormData): Promise<RecognizeStepResult> {
  const TIMED_OUT = "Your sign-in timed out. Start again.";

  if (formData.has("enrollInstead")) {
    const view = await switchRecognizeMode("enroll").catch(() => null);
    return view ? { kind: "switched", view } : { kind: "expired", message: TIMED_OUT };
  }

  let check;
  try {
    check = await completeRecognize(readText(formData, "jwt"));
  } catch (error) {
    console.error("Face verification failed:", error);
    return { kind: "error", message: "We can't reach the face verification service right now. Try again in a moment." };
  }
  if (!check.ok) {
    return check.expired
      ? { kind: "expired", message: TIMED_OUT }
      : { kind: "error", message: "We couldn't confirm that face check. Try again." };
  }

  const state = await continueToMfa(check.account, { username: check.account.username, email: check.account.email }, check.newAccount);
  if (state.mfa) return { kind: "mfa", mfa: state.mfa };
  return { kind: "expired", message: state.formError ?? TIMED_OUT };
}

export async function cancelRecognizeStep(): Promise<void> {
  await cancelRecognize();
}

export async function cancelMfaStep(): Promise<void> {
  await cancelMfa();
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}
