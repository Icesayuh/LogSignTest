export type StoreErrorField = "username" | "email" | "password";

// Thrown by an account store when the directory rejects a registration for a reason the
// user can fix (taken username, weak password). The form shows it under the matching field.
export class AccountStoreError extends Error {
  readonly field?: StoreErrorField;

  constructor(message: string, field?: StoreErrorField) {
    super(message);
    this.name = "AccountStoreError";
    this.field = field;
  }
}
