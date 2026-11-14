"use client";

import { startTransition, useActionState, useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { register, signIn, type AuthFormState } from "@/app/actions";
import { MIN_PASSWORD_LENGTH } from "@/lib/auth/config";
import type { AuthField } from "@/lib/auth/validation";
import { Field } from "./Field";
import { AlertIcon, ArrowRightIcon } from "./Icons";
import { MfaStep } from "./MfaStep";
import { RecognizeStep } from "./RecognizeStep";
import type { MfaView } from "@/lib/auth/mfa-types";
import type { RecognizeView } from "@/lib/recognize/types";
import { PRODUCT_NAME } from "@/lib/brand";

export type AuthMode = "signin" | "register";

const EMPTY_STATE: AuthFormState = { fieldErrors: {}, values: { username: "", email: "" } };
const REGISTER_QUERY = "?mode=register";

const COPY: Record<AuthMode, { heading: string; lede: string; submit: string; pending: string; switchPrompt: string; switchAction: string }> = {
  signin: {
    heading: "Sign in",
    lede: `Use your ${PRODUCT_NAME} account.`,
    submit: "Sign in",
    pending: "Signing in…",
    switchPrompt: `New to ${PRODUCT_NAME}?`,
    switchAction: "Create an account",
  },
  register: {
    heading: "Create your account",
    lede: "It takes a few seconds.",
    submit: "Create account",
    pending: "Creating account…",
    switchPrompt: "Already have an account?",
    switchAction: "Sign in",
  },
};

export function AuthForm({ initialMode }: { initialMode: AuthMode }) {
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [signInState, signInAction, signInPending] = useActionState(signIn, EMPTY_STATE);
  const [registerState, registerAction, registerPending] = useActionState(register, EMPTY_STATE);
  const [editedFields, setEditedFields] = useState<ReadonlySet<AuthField>>(new Set());
  const [silenced, setSilenced] = useState(false);
  const [mfaDismissed, setMfaDismissed] = useState(false);
  // The face step (PingOne Recognize) sits between the password and MFA. It can swap its own view
  // (face login -> enroll instead), hand over to MFA, or send the person back to the form with a message.
  const [faceView, setFaceView] = useState<RecognizeView>();
  const [faceMfa, setFaceMfa] = useState<MfaView>();
  const [faceMessage, setFaceMessage] = useState<string>();
  const [faceDismissed, setFaceDismissed] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  const isRegister = mode === "register";
  const state = isRegister ? registerState : signInState;
  const dispatch = isRegister ? registerAction : signInAction;
  const pending = isRegister ? registerPending : signInPending;
  const copy = COPY[mode];
  // Once the password is accepted the server may ask for a verification code; that step replaces the form.
  const mfa = mfaDismissed ? undefined : (faceMfa ?? state.mfa);
  const face = faceDismissed || faceMfa ? undefined : (faceView ?? state.recognize);

  const handleFaceMfa = useCallback((view: MfaView) => setFaceMfa(view), []);
  const handleFaceSwitch = useCallback((view: RecognizeView) => setFaceView(view), []);
  const handleFaceRestart = useCallback((message?: string) => {
    setFaceDismissed(true);
    setFaceMessage(message);
  }, []);

  useEffect(() => {
    setEditedFields(new Set());
    setSilenced(false);
    setMfaDismissed(false);
    setFaceView(undefined);
    setFaceMfa(undefined);
    setFaceMessage(undefined);
    setFaceDismissed(false);
    const firstProblem = formRef.current?.querySelector<HTMLElement>("[aria-invalid='true'], [data-form-error]");
    firstProblem?.focus();
  }, [signInState, registerState]);

  const errorFor = (field: AuthField) => (silenced || editedFields.has(field) ? undefined : state.fieldErrors[field]);
  const formError = silenced ? undefined : (faceMessage ?? state.formError);

  const markEdited = (field: AuthField) => () =>
    setEditedFields((previous) => (previous.has(field) ? previous : new Set(previous).add(field)));

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    // Without JS the form posts straight to the server action; with JS we dispatch manually
    // so React doesn't reset the fields the visitor typed when the server answers with errors.
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    startTransition(() => dispatch(formData));
  }

  function switchMode() {
    const next: AuthMode = isRegister ? "signin" : "register";
    setMode(next);
    setSilenced(true);
    window.history.replaceState(null, "", next === "register" ? REGISTER_QUERY : window.location.pathname);
  }

  return (
    <div className="auth" data-mode={mode}>
      {face ? (
        <RecognizeStep view={face} onMfa={handleFaceMfa} onSwitch={handleFaceSwitch} onRestart={handleFaceRestart} />
      ) : mfa ? (
        <MfaStep initial={mfa} onRestart={() => setMfaDismissed(true)} />
      ) : (
      <>
      <header className="auth-header">
        <h1 className="auth-heading" key={mode}>
          {copy.heading}
        </h1>
        <p className="auth-lede">{copy.lede}</p>
      </header>

      <form ref={formRef} className="auth-form" action={dispatch} onSubmit={handleSubmit} noValidate>
        {formError && (
          <p className="form-error" role="alert" tabIndex={-1} data-form-error>
            <AlertIcon className="form-error-icon" />
            {formError}
          </p>
        )}

        <Field
          label="Username"
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          defaultValue={state.values.username}
          error={errorFor("username")}
          onInput={markEdited("username")}
        />

        <div className="reveal" data-open={isRegister}>
          <div className="reveal-inner" inert={!isRegister}>
            <Field
              label="Email"
              name="email"
              type="email"
              autoComplete="email"
              defaultValue={registerState.values.email}
              error={errorFor("email")}
              disabled={!isRegister}
              onInput={markEdited("email")}
            />
          </div>
        </div>

        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete={isRegister ? "new-password" : "current-password"}
          hint={isRegister ? `At least ${MIN_PASSWORD_LENGTH} characters.` : undefined}
          error={errorFor("password")}
          onInput={markEdited("password")}
        />

        <div className="reveal" data-open={isRegister}>
          <div className="reveal-inner" inert={!isRegister}>
            <Field
              label="Confirm password"
              name="confirmPassword"
              type="password"
              autoComplete="new-password"
              error={errorFor("confirmPassword")}
              disabled={!isRegister}
              onInput={markEdited("confirmPassword")}
            />
          </div>
        </div>

        <button type="submit" className="submit" disabled={pending} aria-busy={pending}>
          <span>{pending ? copy.pending : copy.submit}</span>
          {!pending && <ArrowRightIcon className="submit-icon" />}
        </button>
      </form>

      <p className="mode-switch">
        {copy.switchPrompt}{" "}
        <button type="button" className="text-button" onClick={switchMode}>
          {copy.switchAction}
        </button>
      </p>
      </>
      )}
    </div>
  );
}
