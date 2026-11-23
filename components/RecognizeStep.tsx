"use client";

import { startTransition, useActionState, useEffect, useRef, useState } from "react";
import { cancelRecognizeStep, recognizeStep } from "@/app/actions";
import type { MfaView } from "@/lib/auth/mfa-types";
import { recognizeErrorCode, recognizeErrorMessage } from "@/lib/recognize-errors";
import { AlertIcon, ArrowRightIcon } from "./Icons";

// The face step, shown in place of the form once the password (and verification code) are done.
// First time: <kl-enroll> registers the face. Every sign-in after: <kl-auth> checks it.
// Both are PingOne Recognize Web SDK components; they run the camera and talk to Keyless themselves.
// All this page does with the result is hand its signed JWT to the server, which decides.

type SdkState = "loading" | "ready" | "unavailable";

export function RecognizeStep({ initial, onRestart }: { initial: MfaView; onRestart: () => void }) {
  const [view, action, pending] = useActionState(recognizeStep, initial);
  const [sdk, setSdk] = useState<SdkState>("loading");
  const [sdkError, setSdkError] = useState<string>();
  const [submitted, setSubmitted] = useState(false);
  const host = useRef<HTMLDivElement>(null);
  const face = view.face;
  const enrolling = face?.mode === "enroll";

  // The SDK needs the browser (camera, WebAssembly), so it is loaded here and not on the server.
  // Importing it registers the <kl-enroll> and <kl-auth> elements.
  useEffect(() => {
    let cancelled = false;
    import("@keyless/sdk-web-components")
      .then(() => !cancelled && setSdk("ready"))
      .catch((error) => {
        console.error("Could not load the PingOne Recognize Web SDK:", error);
        if (!cancelled) setSdk("unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // A new view (another attempt, or an error from the server) starts clean.
  useEffect(() => {
    setSdkError(undefined);
    setSubmitted(false);
  }, [view]);

  // One element per attempt: the SDK allows a single attempt per element, so a retry mounts a new one
  // (the server issued new transaction data for it).
  const attempt = face?.transactionData;
  useEffect(() => {
    const container = host.current;
    if (sdk !== "ready" || !container || !face || view.error || sdkError || submitted) return;

    const element = document.createElement(face.mode === "enroll" ? "kl-enroll" : "kl-auth");
    element.setAttribute("customer", face.customer);
    element.setAttribute("username", face.username);
    element.setAttribute("transaction-data", face.transactionData);
    element.setAttribute("ws-url", face.serviceUrl);
    if (face.authorizationToken) element.setAttribute("authorization-token", face.authorizationToken);
    element.setAttribute("enable-camera-instructions", "");
    element.setAttribute("lang", "en");

    const onSuccess = (event: Event) => {
      const jwt = (event as CustomEvent<{ jwt?: string }>).detail?.jwt;
      if (!jwt) {
        console.error("Recognize reported success without a JWT.");
        setSdkError("UNKNOWN");
        return;
      }
      setSubmitted(true);
      const formData = new FormData();
      formData.set("jwt", jwt);
      startTransition(() => action(formData));
    };
    const onError = (event: Event) => {
      const code = recognizeErrorCode(event);
      console.error("PingOne Recognize reported an error:", code);
      setSdkError(code);
    };
    element.addEventListener("success", onSuccess);
    element.addEventListener("error", onError);
    container.replaceChildren(element);

    return () => {
      element.removeEventListener("success", onSuccess);
      element.removeEventListener("error", onError);
      container.replaceChildren();
    };
    // `attempt` stands for the whole `face` object, which changes only when the server issues a new attempt.
  }, [sdk, attempt, view.error, sdkError, submitted, action]);

  async function restart() {
    await cancelRecognizeStep();
    onRestart();
  }

  const message = view.error ?? (sdkError ? recognizeErrorMessage(sdkError) : undefined);
  const capturing = sdk === "ready" && !message && !submitted;

  return (
    <>
      <header className="auth-header">
        <h1 className="auth-heading" key={face?.mode}>
          {enrolling ? "Register your face" : "Confirm it's you"}
        </h1>
        <p className="auth-lede">{view.prompt}</p>
      </header>

      <div className="auth-form">
        {message && (
          <p className="form-error" role="alert">
            <AlertIcon className="form-error-icon" />
            {message}
          </p>
        )}
        {sdk === "unavailable" && (
          <p className="form-error" role="alert">
            <AlertIcon className="form-error-icon" />
            The face check couldn't load in this browser. Reload the page, or try another browser.
          </p>
        )}

        <div ref={host} className="face-frame" hidden={!capturing} />
        {(sdk === "loading" || submitted || pending) && !message && (
          <p className="field-hint" role="status">
            {sdk === "loading" ? "Loading the face check…" : "Checking…"}
          </p>
        )}

        {message && sdk !== "unavailable" && (
          <form action={action}>
            <button type="submit" className="submit" disabled={pending} aria-busy={pending}>
              <span>{pending ? "Preparing…" : "Try again"}</span>
              {!pending && <ArrowRightIcon className="submit-icon" />}
            </button>
          </form>
        )}
      </div>

      <div className="mode-switch mode-switch-stack">
        <button type="button" className="text-button" onClick={restart}>
          Start over
        </button>
      </div>
    </>
  );
}
