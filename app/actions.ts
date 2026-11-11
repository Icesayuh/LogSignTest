"use server";

import { redirect } from "next/navigation";
import { accountStore as accounts } from "@/lib/auth/store";
import { AccountStoreError } from "@/lib/auth/errors";
import type { Account } from "@/lib/auth/accounts";
import { cancelMfa, selectMfaDevice, startMfa, verifyMfaCode, type MfaOutcome } from "@/lib/auth/mfa";
import { MfaFlowError, mfaRequired } from "@/lib/auth/mfa-flow";
import type { MfaView } from "@/lib/auth/mfa-types";
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

// The password (or registration) just succeeded. Start the MFA step, or finish signing in when MFA is off.
async function continueToMfa(account: Account, values: AuthFormState["values"]): Promise<AuthFormState> {
  if (!mfaRequired()) {
    await startSession(account);
    redirect(ACCOUNT_HOME);
  }

  let outcome: MfaOutcome;
  try {
    outcome = await startMfa(account);
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

  // A new account has no verification device yet, so this lands on the email set-up step.
  return continueToMfa(account, values);
}

// The code step. `intent` says which button was pressed: pick a device, or submit a code.
export async function mfaStep(previous: MfaView, formData: FormData): Promise<MfaView> {
  const intent = readText(formData, "intent");

  let outcome: MfaOutcome;
  try {
    outcome =
      intent === "select" ? await selectMfaDevice(readText(formData, "deviceId")) : await verifyMfaCode(readText(formData, "otp"));
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

export async function cancelMfaStep(): Promise<void> {
  await cancelMfa();
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}
