// What the browser is told about the MFA step. Nothing secret lives here: the transaction
// itself (who passed the password check, the PingOne device-authentication ID) stays in a
// sealed cookie on the server.

export type MfaStepName = "select" | "otp" | "enroll" | "expired";

export type MfaDeviceChoice = {
  id: string;
  label: string; // e.g. "Email j****@example.com"
  prompt: string; // shown once this device is picked, e.g. "We sent a code to j****@example.com."
};

export type MfaView = {
  step: MfaStepName;
  devices?: MfaDeviceChoice[]; // step "select"
  prompt?: string; // steps "otp" and "enroll"
  error?: string;
};
