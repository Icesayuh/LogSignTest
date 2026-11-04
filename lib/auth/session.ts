import { cookies } from "next/headers";
import type { Account } from "./accounts";
import { SESSION_COOKIE, SESSION_MAX_AGE_SECONDS } from "./config";
import { seal, unseal } from "./crypto";

export type Session = {
  accountId: string;
  name: string;
  email: string;
  accountCreatedAt: string;
  signedInAt: string;
  expiresAt: number;
};

export async function startSession(account: Account): Promise<void> {
  const session: Session = {
    accountId: account.id,
    name: account.name,
    email: account.email,
    accountCreatedAt: account.createdAt,
    signedInAt: new Date().toISOString(),
    expiresAt: Date.now() + SESSION_MAX_AGE_SECONDS * 1000,
  };
  const jar = await cookies();
  jar.set(SESSION_COOKIE, seal(session), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
}

export async function readSession(): Promise<Session | null> {
  const jar = await cookies();
  const session = unseal<Session>(jar.get(SESSION_COOKIE)?.value);
  return session && session.expiresAt > Date.now() ? session : null;
}

export async function endSession(): Promise<void> {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
}
