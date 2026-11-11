"use server";

import { redirect } from "next/navigation";
import { accountStore as accounts } from "@/lib/auth/store";
import { AccountStoreError } from "@/lib/auth/errors";
import { isOidcConfigured } from "@/lib/auth/oidc";
import type { Account } from "@/lib/auth/accounts";
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
};

const ACCOUNT_HOME = "/account";

function readText(formData: FormData, field: string): string {
  const value = formData.get(field);
  return typeof value === "string" ? value : "";
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

  await startSession(account);
  redirect(ACCOUNT_HOME);
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
  // With hosted sign-in the new user signs in through PingOne right away, so their first
  // sign-in goes through the MFA policy (including device enrollment) like every later one.
  if (isOidcConfigured()) redirect(`/auth/login?hint=${encodeURIComponent(username)}`);

  await startSession(account);
  redirect(ACCOUNT_HOME);
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}
