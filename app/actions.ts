"use server";

import { redirect } from "next/navigation";
import { accountStore as accounts } from "@/lib/auth/store";
import { AccountDisabledError, AccountStoreError } from "@/lib/auth/errors";
import type { Account } from "@/lib/auth/accounts";
import { cancelMfa, continueMfa, startMfa, type MfaOutcome } from "@/lib/auth/mfa";
import { MfaFlowError, mfaRequired, type MfaAction } from "@/lib/auth/mfa-flow";
import type { MfaView } from "@/lib/auth/mfa-types";
import { beginRecognize, cancelRecognize, continueRecognize, recognizeRequired, type RecognizeAction, type RecognizeOutcome } from "@/lib/auth/recognize-flow";
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
};

const ACCOUNT_HOME = "/account";

function readText(formData: FormData, field: string): string {
  const value = formData.get(field);
  return typeof value === "string" ? value : "";
}

// Everything before the session is done (password, and the verification code when MFA is on). Either a face
// check comes next (the page shows it in place of the form), or the person is signed in.
async function finishSignIn(account: Account, values: AuthFormState["values"]): Promise<AuthFormState> {
  let face: MfaView | null;
  try {
    face = await faceCheckFor(account);
  } catch (error) {
    console.error("Could not start the face check:", error);
    return { fieldErrors: {}, formError: "We couldn't start the face check right now. Try again in a moment.", values };
  }
  if (face) return { fieldErrors: {}, values, mfa: face };

  await startSession(account);
  redirect(ACCOUNT_HOME);
}

// null: no face check is configured. Otherwise the screen to register a face or to check it.
async function faceCheckFor(account: Account): Promise<MfaView | null> {
  if (!recognizeRequired()) return null;
  const outcome = await beginRecognize(account);
  return outcome.done ? null : outcome.view;
}

// The password (or registration) just succeeded. Start the MFA step, or move on when MFA is off.
async function continueToMfa(account: Account, values: AuthFormState["values"], newAccount = false): Promise<AuthFormState> {
  if (!mfaRequired()) return finishSignIn(account, values);

  let outcome: MfaOutcome;
  try {
    outcome = await startMfa(account, { newAccount });
  } catch (error) {
    console.error("Could not start MFA:", error);
    const formError =
      error instanceof MfaFlowError ? error.message : "We couldn't start verification right now. Try again in a moment.";
    return { fieldErrors: {}, formError, values };
  }

  if (outcome.done) return finishSignIn(outcome.account, values);
  return { fieldErrors: {}, values, mfa: outcome.view };
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
    if (error instanceof AccountDisabledError) {
      return {
        fieldErrors: {},
        formError: "Your account has been disabled, usually after too many failed verification attempts. Contact an administrator to regain access.",
        values,
      };
    }
    console.error("Sign-in failed:", error);
    return { fieldErrors: {}, formError: "We can't reach the sign-in service right now. Try again in a moment.", values };
  }
  // One message for both cases so the form doesn't reveal which usernames are registered.
  if (!account) return { fieldErrors: {}, formError: "Wrong username or password. Try again, or create an account.", values };

  return continueToMfa(account, values);
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

  // A new account has no verification method yet, so this lands on choosing one to set up.
  return continueToMfa(account, values, true);
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
    let face: MfaView | null;
    try {
      face = await faceCheckFor(outcome.account);
    } catch (error) {
      console.error("Could not start the face check:", error);
      return { ...previous, error: "We couldn't start the face check right now. Try again in a moment." };
    }
    if (face) return face;

    await startSession(outcome.account);
    redirect(ACCOUNT_HOME);
  }
  return outcome.view;
}

export async function cancelMfaStep(): Promise<void> {
  await cancelMfa();
}

function readRecognizeAction(formData: FormData): RecognizeAction {
  return formData.has("jwt") ? { type: "result", jwt: readText(formData, "jwt") } : { type: "retry" };
}

// The face step: the browser's capture finished (a signed result to check) or the person wants another try.
export async function recognizeStep(previous: MfaView, formData: FormData): Promise<MfaView> {
  let outcome: RecognizeOutcome;
  try {
    outcome = await continueRecognize(readRecognizeAction(formData));
  } catch (error) {
    console.error("Face check step failed:", error);
    return { ...previous, error: "We can't reach the face check right now. Try again in a moment." };
  }

  if (outcome.done) {
    await startSession(outcome.account);
    redirect(ACCOUNT_HOME);
  }
  return outcome.view;
}

export async function cancelRecognizeStep(): Promise<void> {
  await cancelRecognize();
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}
