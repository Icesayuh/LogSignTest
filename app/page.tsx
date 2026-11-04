import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { AuthForm, type AuthMode } from "@/components/AuthForm";
import { LogonScreen } from "@/components/LogonScreen";
import { readSession } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Sign in" };

type SignInPageProps = { searchParams: Promise<{ mode?: string }> };

export default async function SignInPage({ searchParams }: SignInPageProps) {
  if (await readSession()) redirect("/account");

  const { mode } = await searchParams;
  const initialMode: AuthMode = mode === "register" ? "register" : "signin";

  return (
    <LogonScreen>
      <AuthForm initialMode={initialMode} />
    </LogonScreen>
  );
}
