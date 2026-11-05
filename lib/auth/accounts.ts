import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import { ACCOUNTS_COOKIE, ACCOUNTS_MAX_AGE_SECONDS, MAX_ACCOUNTS_PER_BROWSER } from "./config";
import { hashPassword, seal, unseal, verifyPassword } from "./crypto";

export type Account = {
  id: string;
  name: string;
  username: string;
  email: string;
  passwordHash: string;
  createdAt: string;
};

export type NewAccount = { name: string; username: string; email: string; password: string };

// The page only talks to this interface, so an identity provider (Entra ID, Okta, Auth0)
// can replace the store without touching the UI.
export interface AccountStore {
  findByUsername(username: string): Promise<Account | null>;
  findByEmail(email: string): Promise<Account | null>;
  create(input: NewAccount): Promise<Account>;
  verify(username: string, password: string): Promise<Account | null>;
}

async function readAccounts(): Promise<Account[]> {
  const jar = await cookies();
  return unseal<Account[]>(jar.get(ACCOUNTS_COOKIE)?.value) ?? [];
}

async function writeAccounts(accounts: Account[]): Promise<void> {
  const jar = await cookies();
  jar.set(ACCOUNTS_COOKIE, seal(accounts), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: ACCOUNTS_MAX_AGE_SECONDS,
  });
}

async function findByUsername(username: string): Promise<Account | null> {
  const accounts = await readAccounts();
  return accounts.find((account) => account.username === username) ?? null;
}

async function findByEmail(email: string): Promise<Account | null> {
  const accounts = await readAccounts();
  return accounts.find((account) => account.email === email) ?? null;
}

// Vercel functions have no persistent disk, so until a provider takes over, accounts
// live sealed inside the registering browser's cookie: they work on Vercel with no
// database, but only in the browser that created them.
export const browserAccountStore: AccountStore = {
  findByUsername,
  findByEmail,

  async create({ name, username, email, password }) {
    const account: Account = {
      id: randomUUID(),
      name,
      username,
      email,
      passwordHash: await hashPassword(password),
      createdAt: new Date().toISOString(),
    };
    const accounts = await readAccounts();
    await writeAccounts([...accounts, account].slice(-MAX_ACCOUNTS_PER_BROWSER));
    return account;
  },

  async verify(username, password) {
    const account = await findByUsername(username);
    if (!account) return null;
    return (await verifyPassword(password, account.passwordHash)) ? account : null;
  },
};
