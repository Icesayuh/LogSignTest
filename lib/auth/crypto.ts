import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { getAuthSecret } from "./config";

const scryptAsync = promisify(scrypt) as (password: string, salt: Buffer, keyLength: number) => Promise<Buffer>;

const PASSWORD_SALT_BYTES = 16;
const PASSWORD_KEY_BYTES = 32;
const CIPHER = "aes-256-gcm";
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(PASSWORD_SALT_BYTES);
  const key = await scryptAsync(password, salt, PASSWORD_KEY_BYTES);
  return `${salt.toString("base64url")}.${key.toString("base64url")}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [saltText, keyText] = storedHash.split(".");
  if (!saltText || !keyText) return false;
  const expected = Buffer.from(keyText, "base64url");
  const actual = await scryptAsync(password, Buffer.from(saltText, "base64url"), expected.length);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function sealingKey(): Buffer {
  return createHash("sha256").update(getAuthSecret()).digest();
}

export function seal(value: unknown): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(CIPHER, sealingKey(), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

// Tampered cookies, cookies sealed with an old secret, and malformed values all read as "nothing there".
export function unseal<T>(token: string | undefined): T | null {
  if (!token) return null;
  try {
    const raw = Buffer.from(token, "base64url");
    const iv = raw.subarray(0, IV_BYTES);
    const tag = raw.subarray(IV_BYTES, IV_BYTES + AUTH_TAG_BYTES);
    const decipher = createDecipheriv(CIPHER, sealingKey(), iv);
    decipher.setAuthTag(tag);
    const body = Buffer.concat([decipher.update(raw.subarray(IV_BYTES + AUTH_TAG_BYTES)), decipher.final()]);
    return JSON.parse(body.toString("utf8")) as T;
  } catch {
    return null;
  }
}
