"use client";

import { useId, useState } from "react";
import { AlertIcon, EyeIcon, EyeOffIcon } from "./Icons";

type FieldProps = {
  label: string;
  name: string;
  type?: "text" | "email" | "password";
  autoComplete: string;
  error?: string;
  hint?: string;
  defaultValue?: string;
  disabled?: boolean;
  onInput?: () => void;
};

export function Field({ label, name, type = "text", autoComplete, error, hint, defaultValue, disabled, onInput }: FieldProps) {
  const id = useId();
  const errorId = `${id}-error`;
  const hintId = `${id}-hint`;
  const describedBy = [error && errorId, hint && !error && hintId].filter(Boolean).join(" ") || undefined;
  const [revealed, setRevealed] = useState(false);
  const isPassword = type === "password";

  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <div className="field-control">
        <input
          id={id}
          className="field-input"
          name={name}
          type={isPassword && revealed ? "text" : type}
          autoComplete={autoComplete}
          defaultValue={defaultValue}
          disabled={disabled}
          spellCheck={false}
          autoCapitalize={type === "text" ? "words" : "none"}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          onInput={onInput}
        />
        {isPassword && (
          <button
            type="button"
            className="reveal-toggle"
            onClick={() => setRevealed((value) => !value)}
            aria-label={revealed ? "Hide password" : "Show password"}
            aria-pressed={revealed}
            disabled={disabled}
          >
            {revealed ? <EyeOffIcon /> : <EyeIcon />}
          </button>
        )}
      </div>
      {error ? (
        <p className="field-error" id={errorId}>
          <AlertIcon className="field-error-icon" />
          {error}
        </p>
      ) : (
        hint && (
          <p className="field-hint" id={hintId}>
            {hint}
          </p>
        )
      )}
    </div>
  );
}
