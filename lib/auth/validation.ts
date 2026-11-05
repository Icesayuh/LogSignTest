import { MAX_NAME_LENGTH, MAX_USERNAME_LENGTH, MIN_PASSWORD_LENGTH, MIN_USERNAME_LENGTH } from "./config";

export type AuthField = "name" | "username" | "email" | "password" | "confirmPassword";
export type FieldErrors = Partial<Record<AuthField, string>>;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_PATTERN = /^[a-z0-9_.]+$/;

export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

// Usernames are compared case-insensitively, so "Ada" and "ada" are the same account.
export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

function validateUsername(username: string): string | undefined {
  if (!username) return "Enter your username.";
  if (username.length < MIN_USERNAME_LENGTH || username.length > MAX_USERNAME_LENGTH) {
    return `Use ${MIN_USERNAME_LENGTH} to ${MAX_USERNAME_LENGTH} characters.`;
  }
  if (!USERNAME_PATTERN.test(username)) return "Use only letters, numbers, periods and underscores.";
  return undefined;
}

function validateEmail(email: string): string | undefined {
  if (!email) return "Enter your email address.";
  if (!EMAIL_PATTERN.test(email)) return "That doesn't look like an email address. Check for typos.";
  return undefined;
}

export function validateSignIn(username: string, password: string): FieldErrors {
  const errors: FieldErrors = {};
  if (!username) errors.username = "Enter your username.";
  if (!password) errors.password = "Enter your password.";
  return errors;
}

export function validateRegistration(
  name: string,
  username: string,
  email: string,
  password: string,
  confirmPassword: string,
): FieldErrors {
  const errors: FieldErrors = {};
  if (!name) errors.name = "Enter your name.";
  else if (name.length > MAX_NAME_LENGTH) errors.name = `Keep your name under ${MAX_NAME_LENGTH} characters.`;
  const usernameError = validateUsername(username);
  if (usernameError) errors.username = usernameError;
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
