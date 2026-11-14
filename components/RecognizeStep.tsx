"use client";

import { startTransition, useEffect, useRef, useState } from "react";
import { cancelRecognizeStep, recognizeStep } from "@/app/actions";
import type { MfaView } from "@/lib/auth/mfa-types";
import type { RecognizeView } from "@/lib/recognize/types";
import { AlertIcon } from "./Icons";

// The face step, shown in place of the username/password form. It hosts PingOne Recognize's web component
// (<kl-enroll> after registering, <kl-auth> when signing in); the SDK talks to Keyless and the camera.
// Its signed JWT then goes to the server, which verifies it with Keyless before the sign-in continues.

type Props = {
  view: RecognizeView;
  onMfa: (mfa: MfaView) => void;
  onSwitch: (view: RecognizeView) => void;
  onRestart: (message?: string) => void;
};

// Error codes the SDK reports (event.message). Anything else gets the generic message.
function describeError(code: string): string {
  if (/CAMERA|MEDIA_DEVICES|PERMISSION|NOT_ALLOWED/i.test(code)) return "We couldn't use your camera. Allow camera access for this site and try again.";
  if (/FORBIDDEN/i.test(code)) return "Face verification was refused for this account. Start over and try again.";
  if (/WASM|WEB_ASSEMBLY/i.test(code)) return "This browser can't run face verification.";
  return "We couldn't verify your face. Try again in good light, facing the camera.";
}

export function RecognizeStep({ view, onMfa, onSwitch, onRestart }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [attempt, setAttempt] = useState(0); // a new attempt re-creates the element: the SDK allows one try per session
  const [error, setError] = useState<string>();
  const [checking, setChecking] = useState(false);
  const enrolling = view.mode === "enroll";

  useEffect(() => {
    let cancelled = false;
    const host = hostRef.current;
    let element: HTMLElement | undefined;

    function submit(jwt: string) {
      setChecking(true);
      const formData = new FormData();
      formData.set("jwt", jwt);
      startTransition(async () => {
        try {
          const result = await recognizeStep(formData);
          if (result.kind === "mfa") onMfa(result.mfa);
          else if (result.kind === "expired") onRestart(result.message);
          else if (result.kind === "error") {
            setError(result.message);
            setChecking(false);
          }
        } catch (caught) {
          console.error("Face verification step failed:", caught);
          setError("Something went wrong. Try again.");
          setChecking(false);
        }
      });
    }

    import("@keyless/sdk-web-components")
      .then(() => {
        if (cancelled || !host) return;
        element = document.createElement(enrolling ? "kl-enroll" : "kl-auth");
        element.setAttribute("customer", view.customer);
        element.setAttribute("username", view.username);
        element.setAttribute("authorization-token", view.authorizationToken);
        element.setAttribute("transaction-data", view.transactionData);
        element.setAttribute("ws-url", view.serviceUrl);
        element.setAttribute("lang", "en");
        element.setAttribute("size", "375");
        element.setAttribute("theme", "light");
        element.setAttribute("enable-camera-instructions", "true");
        element.addEventListener("error", (event) => {
          const code = (event as unknown as { message?: string }).message ?? "";
          console.error("PingOne Recognize error:", code);
          setError(describeError(code));
        });
        element.addEventListener("success", (event) => {
          const jwt = (event as CustomEvent<{ jwt?: string }>).detail?.jwt;
          if (jwt) submit(jwt);
          else setError("We didn't get a result from face verification. Try again.");
        });
        host.replaceChildren(element);
      })
      .catch((caught) => {
        console.error("Could not load the PingOne Recognize SDK:", caught);
        if (!cancelled) setError("Face verification isn't available right now.");
      });

    return () => {
      cancelled = true;
      element?.remove();
    };
    // The view carries a fresh authorization token per attempt, so it is the whole dependency.
  }, [view, attempt, enrolling, onMfa, onRestart]);

  async function restart() {
    await cancelRecognizeStep();
    onRestart();
  }

  function retry() {
    setError(undefined);
    setAttempt((n) => n + 1);
  }

  function enrollInstead() {
    const formData = new FormData();
    formData.set("enrollInstead", "1");
    startTransition(async () => {
      const result = await recognizeStep(formData);
      if (result.kind === "switched") {
        setError(undefined);
        onSwitch(result.view);
      } else if (result.kind === "expired") onRestart(result.message);
    });
  }

  return (
    <>
      <header className="auth-header">
        <h1 className="auth-heading" key={view.mode}>
          {enrolling ? "Set up face verification" : "Verify your face"}
        </h1>
        <p className="auth-lede">
          {enrolling
            ? "We'll save a biometric template of your face so you can sign in with it."
            : "Look at the camera to confirm it's you."}
        </p>
      </header>

      <div className="auth-form">
        {error && (
          <p className="form-error" role="alert">
            <AlertIcon className="form-error-icon" />
            {error}
          </p>
        )}
        {/* The SDK renders its own camera view in here. */}
        <div ref={hostRef} className="recognize-host" aria-busy={checking} hidden={Boolean(error) || checking} />
        {checking && <p className="field-hint">Checking…</p>}
        {error && !checking && (
          <button type="button" className="submit" onClick={retry}>
            <span>Try again</span>
          </button>
        )}
      </div>

      <div className="mode-switch mode-switch-stack">
        {!enrolling && (
          <button type="button" className="text-button" onClick={enrollInstead} disabled={checking}>
            No face set up yet? Set it up now
          </button>
        )}
        <button type="button" className="text-button" onClick={restart}>
          Start over
        </button>
      </div>
    </>
  );
}
