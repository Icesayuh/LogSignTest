import { cookies } from "next/headers";
import type { Account } from "./accounts";
import { seal, unseal } from "./crypto";
import { call, isPingOneConfigured, readConfig } from "./pingone";

// Remembers who has registered a face, so a sign-in knows whether to check a face or to register one
// (someone who closed the tab mid-registration, or an account made before the face check existed).
//
// PingOne Directory: a boolean user attribute. Create it once under Directory > Attributes > Add Attribute
//   (Custom, Boolean, name `keylessEnrolled`; PINGONE_RECOGNIZE_ATTRIBUTE changes the name).
// Built-in cookie demo store (no PingOne): a sealed cookie in the browser that registered the account.

const attribute = () => process.env.PINGONE_RECOGNIZE_ATTRIBUTE || "keylessEnrolled";

const COOKIE = "acp_rcg_enrolled";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;
const MAX_IDS = 20; // a sealed cookie stays well under the browser's 4 KB limit

export async function isEnrolled(account: Account): Promise<boolean> {
  if (!isPingOneConfigured()) {
    const jar = await cookies();
    return (unseal<string[]>(jar.get(COOKIE)?.value) ?? []).includes(account.id);
  }
  const r = await call(readConfig(), `/users/${encodeURIComponent(account.id)}`);
  if (!r.ok) throw new Error(`PingOne user lookup failed (${r.status}) while checking face enrollment.`);
  return r.data?.[attribute()] === true;
}

export async function markEnrolled(account: Account): Promise<void> {
  if (!isPingOneConfigured()) {
    const jar = await cookies();
    const ids = unseal<string[]>(jar.get(COOKIE)?.value) ?? [];
    if (!ids.includes(account.id)) ids.push(account.id);
    jar.set(COOKIE, seal(ids.slice(-MAX_IDS)), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: COOKIE_MAX_AGE_SECONDS,
    });
    return;
  }
  const r = await call(readConfig(), `/users/${encodeURIComponent(account.id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ [attribute()]: true }),
  });
  if (!r.ok) {
    throw new Error(
      `PingOne rejected the "${attribute()}" attribute (${r.status} ${r.data?.code ?? ""}). Create it under Directory > Attributes as a Boolean, or set PINGONE_RECOGNIZE_ATTRIBUTE.`,
    );
  }
}
