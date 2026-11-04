import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { signOut } from "@/app/actions";
import { LocalTime } from "@/components/LocalTime";
import { LogonScreen } from "@/components/LogonScreen";
import { readSession } from "@/lib/auth/session";

export const metadata: Metadata = { title: "Account" };

function firstName(fullName: string): string {
  return fullName.split(/\s+/)[0] || fullName;
}

export default async function AccountPage() {
  const session = await readSession();
  if (!session) redirect("/");

  return (
    <LogonScreen>
      <div className="welcome">
        <h1 className="welcome-heading">Welcome, {firstName(session.name)}.</h1>
        <p className="auth-lede">You're signed in.</p>

        <dl className="facts">
          <div className="fact">
            <dt>Name</dt>
            <dd>{session.name}</dd>
          </div>
          <div className="fact">
            <dt>Email</dt>
            <dd>{session.email}</dd>
          </div>
          <div className="fact">
            <dt>Signed in</dt>
            <dd>
              <LocalTime iso={session.signedInAt} />
            </dd>
          </div>
          <div className="fact">
            <dt>Account created</dt>
            <dd>
              <LocalTime iso={session.accountCreatedAt} dateOnly />
            </dd>
          </div>
        </dl>

        <form action={signOut}>
          <button type="submit" className="secondary">
            Sign out
          </button>
        </form>
      </div>
    </LogonScreen>
  );
}
