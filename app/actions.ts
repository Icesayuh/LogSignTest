"use server";

import { redirect } from "next/navigation";
import { browserAccountStore as accounts } from "@/lib/auth/accounts";
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
  values: { name: string; username: string; email: string };
};

const ACCOUNT_HOME = "/account";

function readText(formData: FormData, field: string): string {
  const value = formData.get(field);
  return typeof value === "string" ? value : "";
}

export async function signIn(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  const username = normalizeUsername(readText(formData, "username"));
  const password = readText(formData, "password");
  const values = { name: "", username, email: "" };

  const fieldErrors = validateSignIn(username, password);
  if (hasErrors(fieldErrors)) return { fieldErrors, values };

  const account = await accounts.verify(username, password);
  // One message for both cases so the form doesn't reveal which usernames are registered.
  if (!account) return { fieldErrors: {}, formError: "Wrong username or password. Try again, or create an account.", values };

  await startSession(account);
  redirect(ACCOUNT_HOME);
}

export async function register(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  const name = readText(formData, "name").trim();
  const username = normalizeUsername(readText(formData, "username"));
  const email = normalizeEmail(readText(formData, "email"));
  const password = readText(formData, "password");
  const confirmPassword = readText(formData, "confirmPassword");
  const values = { name, username, email };

  const fieldErrors = validateRegistration(name, username, email, password, confirmPassword);
  if (hasErrors(fieldErrors)) return { fieldErrors, values };

  if (await accounts.findByUsername(username)) {
    return { fieldErrors: { username: "That username is taken. Try another one." }, values };
  }
  if (await accounts.findByEmail(email)) {
    return { fieldErrors: { email: "An account with this email already exists. Sign in instead." }, values };
  }

  const account = await accounts.create({ name, username, email, password });
  await startSession(account);
  redirect(ACCOUNT_HOME);
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}
