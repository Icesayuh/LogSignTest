"use client";

import { useActionState } from "react";
import { cancelMfaStep, mfaStep } from "@/app/actions";
import type { MfaView } from "@/lib/auth/mfa-types";
import { Field } from "./Field";
import { AlertIcon, ArrowRightIcon } from "./Icons";

const HEADINGS: Record<MfaView["step"], string> = {
  select: "Verify it's you",
  otp: "Enter your code",
  enroll: "Set up verification",
  expired: "Start again",
};

// The second step of signing in, shown in place of the username/password form.
export function MfaStep({ initial, onRestart }: { initial: MfaView; onRestart: () => void }) {
  const [view, action, pending] = useActionState(mfaStep, initial);

  async function restart() {
    await cancelMfaStep();
    onRestart();
  }

  return (
    <>
      <header className="auth-header">
        <h1 className="auth-heading" key={view.step}>
          {HEADINGS[view.step]}
        </h1>
        <p className="auth-lede">
          {view.step === "select" && "Choose how you'd like to get your code."}
          {(view.step === "otp" || view.step === "enroll") && view.prompt}
        </p>
      </header>

      {view.step === "select" && (
        <form className="auth-form" action={action}>
          <input type="hidden" name="intent" value="select" />
          {view.error && <FormError message={view.error} />}
          <div className="device-list">
            {view.devices?.map((device) => (
              <button key={device.id} type="submit" name="deviceId" value={device.id} className="secondary" disabled={pending}>
                {device.label}
              </button>
            ))}
          </div>
        </form>
      )}

      {(view.step === "otp" || view.step === "enroll") && (
        <form className="auth-form" action={action}>
          <input type="hidden" name="intent" value="verify" />
          <Field
            label="Verification code"
            name="otp"
            autoComplete="one-time-code"
            autoCapitalize="none"
            inputMode="numeric"
            autoFocus
            error={view.error}
          />
          <button type="submit" className="submit" disabled={pending} aria-busy={pending}>
            <span>{pending ? "Checking…" : "Verify"}</span>
            {!pending && <ArrowRightIcon className="submit-icon" />}
          </button>
        </form>
      )}

      {view.step === "expired" && view.error && (
        <div className="auth-form">
          <FormError message={view.error} />
        </div>
      )}

      <p className="mode-switch">
        <button type="button" className="text-button" onClick={restart}>
          {view.step === "expired" ? "Back to sign in" : "Start over"}
        </button>
      </p>
    </>
  );
}

function FormError({ message }: { message: string }) {
  return (
    <p className="form-error" role="alert">
      <AlertIcon className="form-error-icon" />
      {message}
    </p>
  );
}
