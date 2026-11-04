import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import { ACCOUNTS_COOKIE, ACCOUNTS_MAX_AGE_SECONDS, MAX_ACCOUNTS_PER_BROWSER } from "./config";
import { hashPassword, seal, unseal, verifyPassword } from "./crypto";

export type Account = {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  createdAt: string;
};

export type NewAccount = { name: string; email: string; password: string };

// The page only talks to this interface, so an identity provider (Entra ID, Okta, Auth0)
// can replace the store without touching the UI.
export interface AccountStore {
  findByEmail(email: string): Promise<Account | null>;
  create(input: NewAccount): Promise<Account>;
  verify(email: string, password: string): Promise<Account | null>;
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

async function findByEmail(email: string): Promise<Account | null> {
  const accounts = await readAccounts();
  return accounts.find((account) => account.email === email) ?? null;
}

// Vercel functions have no persistent disk, so until a provider takes over, accounts
// live sealed inside the registering browser's cookie: they work on Vercel with no
// database, but only in the browser that created them.
export const browserAccountStore: AccountStore = {
  findByEmail,

  async create({ name, email, password }) {
    const account: Account = {
      id: randomUUID(),
      name,
      email,
      passwordHash: await hashPassword(password),
      createdAt: new Date().toISOString(),
    };
    const accounts = await readAccounts();
    await writeAccounts([...accounts, account].slice(-MAX_ACCOUNTS_PER_BROWSER));
    return account;
  },

  async verify(email, password) {
    const account = await findByEmail(email);
    if (!account) return null;
    return (await verifyPassword(password, account.passwordHash)) ? account : null;
  },
};
