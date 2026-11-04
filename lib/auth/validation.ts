import { MAX_NAME_LENGTH, MIN_PASSWORD_LENGTH } from "./config";

export type AuthField = "name" | "email" | "password" | "confirmPassword";
export type FieldErrors = Partial<Record<AuthField, string>>;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

function validateEmail(email: string): string | undefined {
  if (!email) return "Enter your email address.";
  if (!EMAIL_PATTERN.test(email)) return "That doesn't look like an email address. Check for typos.";
  return undefined;
}

export function validateSignIn(email: string, password: string): FieldErrors {
  const errors: FieldErrors = {};
  const emailError = validateEmail(email);
  if (emailError) errors.email = emailError;
  if (!password) errors.password = "Enter your password.";
  return errors;
}

export function validateRegistration(name: string, email: string, password: string, confirmPassword: string): FieldErrors {
  const errors: FieldErrors = {};
  if (!name) errors.name = "Enter your name.";
  else if (name.length > MAX_NAME_LENGTH) errors.name = `Keep your name under ${MAX_NAME_LENGTH} characters.`;
  const emailError = validateEmail(email);
  if (emailError) errors.email = emailError;
  if (password.length < MIN_PASSWORD_LENGTH) errors.password = `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (!confirmPassword) errors.confirmPassword = "Type your password again.";
  else if (confirmPassword !== password) errors.confirmPassword = "Passwords don't match.";
  return errors;
}

export function hasErrors(errors: FieldErrors): boolean {
  return Object.keys(errors).length > 0;
}
