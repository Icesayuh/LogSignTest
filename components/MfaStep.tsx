"use client";

import { startTransition, useActionState, useEffect, useState } from "react";
import { cancelMfaStep, mfaStep } from "@/app/actions";
import type { MfaView } from "@/lib/auth/mfa-types";
import { createPasskey, passkeysSupported, signWithPasskey } from "@/lib/webauthn";
import { Field } from "./Field";
import { AlertIcon, ArrowRightIcon } from "./Icons";

function headingFor(view: MfaView): string {
  switch (view.step) {
    case "select":
      return "Verify it's you";
    case "otp":
      return "Enter your code";
    case "passkey":
      return "Use your passkey";
    case "method":
      return view.optional ? "Add another method" : "Set up verification";
    case "phone":
      return "Your mobile number";
    case "enroll":
      return "Set up verification";
    case "totp":
      return "Set up your authenticator app";
    case "passkey-setup":
      return "Create a passkey";
    case "expired":
      return "Start again";
  }
}

// The steps after the password, shown in place of the username/password form: choose how to verify,
// set a method up, or type a code / confirm with a passkey.
export function MfaStep({ initial, onRestart }: { initial: MfaView; onRestart: () => void }) {
  const [view, action, pending] = useActionState(mfaStep, initial);
  const [passkeyError, setPasskeyError] = useState<string>();
  const [waitingForDevice, setWaitingForDevice] = useState(false);
  const [passkeyOk, setPasskeyOk] = useState(true);

  // Whether the browser can do passkeys is only known on the client, so check after the first render.
  useEffect(() => setPasskeyOk(passkeysSupported()), []);
  useEffect(() => setPasskeyError(undefined), [view]);

  async function restart() {
    await cancelMfaStep();
    onRestart();
  }

  // The browser talks to the passkey (a fingerprint, face, PIN or security key prompt); the result goes to the server.
  async function runPasskey() {
    if (!view.passkey) return;
    setPasskeyError(undefined);
    setWaitingForDevice(true);
    try {
      const credential =
        view.step === "passkey-setup" ? await createPasskey(view.passkey.options) : await signWithPasskey(view.passkey.options);
      const formData = new FormData();
      formData.set("credential", credential);
      formData.set("origin", window.location.origin);
      startTransition(() => action(formData));
    } catch (error) {
      console.error("Passkey step failed:", error);
      setPasskeyError(
        error instanceof DOMException && error.name === "NotAllowedError"
          ? "The passkey prompt was closed or timed out. Try again."
          : "We couldn't use a passkey on this device. Try again, or pick another method.",
      );
    } finally {
      setWaitingForDevice(false);
    }
  }

  const busy = pending || waitingForDevice;
  const showSwitch = view.canSwitch && (view.step === "otp" || view.step === "passkey");

  return (
    <>
      <header className="auth-header">
        <h1 className="auth-heading" key={view.step}>
          {headingFor(view)}
        </h1>
        <p className="auth-lede">{view.step === "select" ? "Choose how you'd like to verify." : view.prompt}</p>
      </header>

      {view.step === "select" && (
        <form className="auth-form" action={action}>
          {view.error && <FormError message={view.error} />}
          <div className="choice-list">
            {view.devices?.map((device) => (
              <button key={device.id} type="submit" name="deviceId" value={device.id} className="secondary choice" disabled={busy}>
                <span className="choice-title">{device.label}</span>
              </button>
            ))}
          </div>
        </form>
      )}

      {view.step === "method" && (
        <form className="auth-form" action={action}>
          {view.error && <FormError message={view.error} />}
          <div className="choice-list">
            {view.methods?.map((method) => (
              <button key={method.id} type="submit" name="method" value={method.id} className="secondary choice" disabled={busy}>
                <span className="choice-title">{method.label}</span>
                <span className="choice-hint">{method.description}</span>
              </button>
            ))}
          </div>
          {view.optional && (
            <button type="submit" name="skip" value="1" className="submit" disabled={busy}>
              <span>Skip for now</span>
              <ArrowRightIcon className="submit-icon" />
            </button>
          )}
        </form>
      )}

      {view.step === "phone" && (
        <form className="auth-form" action={action}>
          <Field
            label="Mobile number"
            name="phone"
            type="tel"
            autoComplete="tel"
            inputMode="tel"
            autoFocus
            hint="Include the country code, like +1 512 520 1234."
            error={view.error}
          />
          <button type="submit" className="submit" disabled={busy} aria-busy={busy}>
            <span>{pending ? "Sending…" : "Send code"}</span>
            {!busy && <ArrowRightIcon className="submit-icon" />}
          </button>
        </form>
      )}

      {(view.step === "otp" || view.step === "enroll" || view.step === "totp") && (
        <form className="auth-form" action={action}>
          {view.step === "totp" && view.totp && (
            <>
              <div className="qr">
                {/* A data URL made on the server from PingOne's key URI; nothing external is loaded. */}
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={view.totp.qr} width={192} height={192} alt="QR code for your authenticator app" />
              </div>
              <p className="field-hint">
                Can't scan it? Enter this key in your app instead: <code className="secret-key">{view.totp.secret}</code>
              </p>
            </>
          )}
          <Field
            label="Verification code"
            name="otp"
            autoComplete="one-time-code"
            autoCapitalize="none"
            inputMode="numeric"
            autoFocus={view.step !== "totp"}
            error={view.error}
          />
          <button type="submit" className="submit" disabled={busy} aria-busy={busy}>
            <span>{pending ? "Checking…" : "Verify"}</span>
            {!busy && <ArrowRightIcon className="submit-icon" />}
          </button>
        </form>
      )}

      {(view.step === "passkey" || view.step === "passkey-setup") && (
        <div className="auth-form">
          {(view.error || passkeyError || !passkeyOk) && (
            <FormError message={view.error ?? passkeyError ?? "This browser can't use passkeys. Pick another method."} />
          )}
          <button type="button" className="submit" onClick={runPasskey} disabled={busy || !passkeyOk || !view.passkey} aria-busy={busy}>
            <span>{busy ? "Waiting for your device…" : view.step === "passkey-setup" ? "Create passkey" : "Use passkey"}</span>
            {!busy && <ArrowRightIcon className="submit-icon" />}
          </button>
        </div>
      )}

      {view.step === "expired" && view.error && (
        <div className="auth-form">
          <FormError message={view.error} />
        </div>
      )}

      <div className="mode-switch mode-switch-stack">
        {showSwitch && (
          <form action={action}>
            <button type="submit" name="back" value="1" className="text-button" disabled={busy}>
              Use a different method
            </button>
          </form>
        )}
        <button type="button" className="text-button" onClick={restart}>
          {view.step === "expired" ? "Back to sign in" : "Start over"}
        </button>
      </div>
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
