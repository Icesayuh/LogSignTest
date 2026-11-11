// What the browser is told about the MFA step. Nothing secret lives in the transaction the server
// keeps (see mfa.ts); the only secrets shown here are the authenticator-app key the person is about
// to scan and the WebAuthn challenge their device is about to sign.

export type MfaStepName =
  | "select" // sign-in: choose which enrolled method to use
  | "otp" // sign-in: type the code
  | "passkey" // sign-in: confirm with the passkey
  | "method" // set-up: choose a method to set up (or add another, when `optional`)
  | "phone" // set-up: text message needs a number
  | "enroll" // set-up: type the code that was sent (email / text message)
  | "totp" // set-up: scan the QR code, type the code the app shows
  | "passkey-setup" // set-up: create the passkey on this device
  | "expired";

// In the order they are offered.
export type EnrollMethod = "TOTP" | "EMAIL" | "FIDO2" | "SMS";

export type MfaDeviceChoice = {
  id: string;
  label: string; // e.g. "Email j****@example.com"
  prompt: string; // shown once this device is picked, e.g. "We sent a code to j****@example.com."
};

export type MfaMethodChoice = { id: EnrollMethod; label: string; description: string };

export type MfaView = {
  step: MfaStepName;
  devices?: MfaDeviceChoice[]; // step "select"
  methods?: MfaMethodChoice[]; // step "method"
  optional?: boolean; // step "method": already set up once, this is an extra (can be skipped)
  prompt?: string;
  totp?: { qr: string; secret: string }; // step "totp": QR code as an image data URL, and the key for manual entry
  passkey?: { options: string }; // steps "passkey" and "passkey-setup": WebAuthn options (JSON) from PingOne
  canSwitch?: boolean; // steps "otp" and "passkey": the person has other methods to pick instead
  error?: string;
};
