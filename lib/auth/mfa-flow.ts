import type { Account } from "./accounts";
import type { MfaDeviceChoice, MfaView } from "./mfa-types";
import { isPingOneConfigured } from "./pingone";
import * as api from "./pingone-mfa";

// The MFA state machine, free of any cookie handling (see mfa.ts for that):
//   password OK -> no usable device ......... enroll (email code) -> done
//               -> several devices .......... select -> otp -> done
//               -> one device / PingOne picks otp -> done

export const MFA_TTL_MS = 10 * 60 * 1000;

// On whenever PingOne is the account store; PINGONE_MFA_ENABLED=false turns it off.
export function mfaRequired(): boolean {
  return isPingOneConfigured() && process.env.PINGONE_MFA_ENABLED !== "false";
}

// A message that is safe and useful to show the person signing in.
export class MfaFlowError extends Error {}

export type MfaTransaction = {
  account: Account;
  step: "select" | "otp" | "enroll";
  prompt?: string;
  devices?: MfaDeviceChoice[];
  deviceAuthId?: string;
  enrollDeviceId?: string;
  expiresAt: number;
};

export type FlowResult =
  | { done: true; account: Account }
  | { done: false; view: MfaView; transaction: MfaTransaction | null }; // null: nothing left to remember

export function maskEmail(email: string): string {
  const [name = "", domain = ""] = email.split("@");
  return `${name.slice(0, 1)}${"*".repeat(Math.max(name.length - 1, 3))}@${domain}`;
}

function describe(device: api.MfaDevice): MfaDeviceChoice {
  switch (device.type) {
    case "EMAIL":
      return { id: device.id, label: `Email ${device.email ?? ""}`.trim(), prompt: `We sent a code to ${device.email ?? "your email"}.` };
    case "SMS":
      return { id: device.id, label: `Text message ${device.phone ?? ""}`.trim(), prompt: `We texted a code to ${device.phone ?? "your phone"}.` };
    case "VOICE":
      return { id: device.id, label: `Phone call ${device.phone ?? ""}`.trim(), prompt: `We're calling ${device.phone ?? "your phone"} with a code.` };
    case "TOTP":
      return { id: device.id, label: "Authenticator app", prompt: "Enter the code from your authenticator app." };
    default:
      return { id: device.id, label: device.type, prompt: "Enter your verification code." };
  }
}

const expiry = () => Date.now() + MFA_TTL_MS;

function otpStep(account: Account, deviceAuthId: string, choice: MfaDeviceChoice | undefined): FlowResult {
  const prompt = choice?.prompt ?? "Enter your verification code.";
  return { done: false, view: { step: "otp", prompt }, transaction: { account, step: "otp", prompt, deviceAuthId, expiresAt: expiry() } };
}

function fromDeviceAuthentication(account: Account, auth: api.DeviceAuthentication): FlowResult {
  switch (auth.status) {
    case "COMPLETED":
      return { done: true, account }; // the MFA policy decided no further step is needed

    case "OTP_REQUIRED": {
      const device = auth.devices.find((d) => d.id === auth.selectedDeviceId) ?? (auth.devices.length === 1 ? auth.devices[0] : undefined);
      return otpStep(account, auth.id, device && describe(device));
    }

    case "DEVICE_SELECTION_REQUIRED": {
      const devices = auth.devices.filter(api.isOtpDevice).map(describe);
      if (!devices.length) throw new MfaFlowError("None of your verification methods can be used on this page.");
      return {
        done: false,
        view: { step: "select", devices },
        transaction: { account, step: "select", devices, deviceAuthId: auth.id, expiresAt: expiry() },
      };
    }

    default:
      throw new MfaFlowError("Your account's verification method can't be used on this page.");
  }
}

// Call right after the password check succeeded.
export async function beginMfa(account: Account): Promise<FlowResult> {
  const devices = await api.listActiveDevices(account.id);

  if (devices.length === 0) {
    if (!account.email) throw new MfaFlowError("Your account has no email address to set up verification with.");
    const { id } = await api.createEmailDevice(account.id, account.email);
    const prompt = `We sent a code to ${maskEmail(account.email)} to set up verification for your account.`;
    return { done: false, view: { step: "enroll", prompt }, transaction: { account, step: "enroll", prompt, enrollDeviceId: id, expiresAt: expiry() } };
  }

  return fromDeviceAuthentication(account, await api.beginDeviceAuthentication(account.id));
}

export async function chooseDevice(tx: MfaTransaction, deviceId: string): Promise<FlowResult> {
  const choice = tx.devices?.find((d) => d.id === deviceId);
  if (tx.step !== "select" || !tx.deviceAuthId || !choice) {
    return { done: false, view: { step: "select", devices: tx.devices, error: "Pick one of the options below." }, transaction: tx };
  }

  const auth = await api.selectDevice(tx.deviceAuthId, deviceId);
  if (auth.status !== "OTP_REQUIRED") {
    return { done: false, view: { step: "select", devices: tx.devices, error: "That option can't be used on this page. Pick another." }, transaction: tx };
  }
  return otpStep(tx.account, tx.deviceAuthId, choice);
}

export async function submitOtp(tx: MfaTransaction, rawCode: string): Promise<FlowResult> {
  const code = rawCode.replace(/\s+/g, "");
  const retry = (error: string): FlowResult => ({ done: false, view: { step: tx.step === "enroll" ? "enroll" : "otp", prompt: tx.prompt, error }, transaction: tx });

  if (!code) return retry("Enter the code.");

  if (tx.step === "enroll" && tx.enrollDeviceId) {
    return (await api.activateDevice(tx.account.id, tx.enrollDeviceId, code)) === "ok"
      ? { done: true, account: tx.account }
      : retry("That code didn't work. Check it and try again.");
  }

  if (tx.step === "otp" && tx.deviceAuthId) {
    const result = await api.checkOtp(tx.deviceAuthId, code);
    if (result === "ok") return { done: true, account: tx.account };
    if (result === "failed") return { done: false, view: { step: "expired", error: "Too many wrong codes. Start again." }, transaction: null };
    return retry("That code didn't work. Check it and try again.");
  }

  return { done: false, view: { step: "expired", error: "Your sign-in timed out. Start again." }, transaction: null };
}
