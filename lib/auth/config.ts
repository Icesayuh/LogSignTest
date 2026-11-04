export const SESSION_COOKIE = "acp_session";
export const ACCOUNTS_COOKIE = "acp_accounts";
export const SESSION_MAX_AGE_SECONDS = 60 * 60 * 8;
export const ACCOUNTS_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;
// Browsers cap a cookie near 4 KB; ten sealed accounts stay well under it.
export const MAX_ACCOUNTS_PER_BROWSER = 10;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_NAME_LENGTH = 60;

const DEV_FALLBACK_SECRET = "logsigntest-local-dev-secret-change-me";

export function getAuthSecret(): string {
  const secret = process.env.AUTH_SECRET;
  if (secret) return secret;
  if (process.env.NODE_ENV === "production") {
    throw new Error("AUTH_SECRET is not set. Add it under Vercel → Project → Settings → Environment Variables.");
  }
  return DEV_FALLBACK_SECRET;
}
