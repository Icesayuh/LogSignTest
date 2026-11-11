import QRCode from "qrcode";
import type { Account } from "./accounts";
import type { EnrollMethod, MfaDeviceChoice, MfaMethodChoice, MfaView } from "./mfa-types";
import { isPingOneConfigured } from "./pingone";
import * as api from "./pingone-mfa";

// The MFA state machine, free of any cookie handling (see mfa.ts for that).
//
//  Sign-in, password accepted:
//    no usable method ........ set-up (below)
//    one method .............. otp (code) or passkey -> done
//    two or more methods ..... select (the person chooses) -> otp or passkey -> done
//                              ("use a different method" goes back to select)
//
//  Set-up (right after registering, or a sign-in with no method yet):
//    several methods offered . method (the person chooses)
//    one method offered ...... straight to it
//      email .... enroll (code sent to the email) ........ -> done with that method
//      app ...... totp (QR code, then the code it shows) . -> done with that method
//      passkey .. passkey-setup (the device creates it) .. -> done with that method
//      sms ...... phone (their number) -> enroll (code) .. -> done with that method
//    then, if other methods remain: method again (optional, can be skipped) -> signed in

export const MFA_TTL_MS = 10 * 60 * 1000;
const RP_NAME = "LogSignTest"; // shown by the browser when it creates a passkey

// On whenever PingOne is the account store; PINGONE_MFA_ENABLED=false turns it off.
export function mfaRequired(): boolean {
  return isPingOneConfigured() && process.env.PINGONE_MFA_ENABLED !== "false";
}

// A message that is safe and useful to show the person signing in.
export class MfaFlowError extends Error {}

// What the flow needs to know about the request it is serving.
export type MfaContext = { rpId: string }; // the site's host name: a passkey belongs to it

type Step = "select" | "otp" | "passkey" | "method" | "phone" | "enroll" | "totp" | "passkey-setup";

export type MfaTransaction = {
  account: Account;
  rpId: string;
  step: Step;
  prompt?: string;
  // sign-in
  devices?: MfaDeviceChoice[]; // kept after a pick so the person can switch to another one
  deviceAuthId?: string;
  selectedDeviceId?: string; // the device PingOne already picked (and sent a code or challenge to)
  selectedStatus?: string;
  // set-up
  methods?: EnrollMethod[]; // everything the policy allows
  offered?: EnrollMethod[]; // what the method screen currently lists
  enrolled?: EnrollMethod[];
  optional?: boolean; // the method screen is an extra, not a requirement
  pendingMethod?: EnrollMethod;
  enrollDeviceId?: string;
  totpKeyUri?: string;
  // WebAuthn options for the current passkey step (to sign in with, or to create one)
  passkeyOptions?: string;
  expiresAt: number;
};

export type MfaAction =
  | { type: "select"; deviceId: string }
  | { type: "back" }
  | { type: "method"; method: string }
  | { type: "phone"; phone: string }
  | { type: "verify"; code: string }
  | { type: "passkey"; credential: string; origin: string }
  | { type: "skip" };

export type FlowResult =
  | { done: true; account: Account }
  | { done: false; view: MfaView; transaction: MfaTransaction | null }; // null: nothing left to remember

// ---- small helpers ----

export function maskEmail(email: string): string {
  const [name = "", domain = ""] = email.split("@");
  return `${name.slice(0, 1)}${"*".repeat(Math.max(name.length - 1, 3))}@${domain}`;
}

export function maskPhone(phone: string): string {
  const digits = phone.replace(/\D/g, "");
  return digits.length <= 2 ? phone : `${"*".repeat(Math.max(digits.length - 2, 4))}${digits.slice(-2)}`;
}

function describeDevice(device: api.MfaDevice): MfaDeviceChoice {
  const email = device.email ? maskEmail(device.email) : "your email";
  const phone = device.phone ? maskPhone(device.phone) : "your phone";
  switch (device.type) {
    case "EMAIL":
      return { id: device.id, label: `Email ${device.email ? email : ""}`.trim(), prompt: `We sent a code to ${email}.` };
    case "SMS":
      return { id: device.id, label: `Text message ${device.phone ? phone : ""}`.trim(), prompt: `We texted a code to ${phone}.` };
    case "VOICE":
      return { id: device.id, label: `Phone call ${device.phone ? phone : ""}`.trim(), prompt: `We're calling ${phone} with a code.` };
    case "TOTP":
      return { id: device.id, label: "Authenticator app", prompt: "Enter the code from your authenticator app." };
    case "FIDO2":
      return { id: device.id, label: "Passkey", prompt: "Use your passkey to confirm it's you." };
    default:
      return { id: device.id, label: device.type, prompt: "Enter your verification code." };
  }
}

function methodChoice(method: EnrollMethod, account: Account): MfaMethodChoice {
  switch (method) {
    case "TOTP":
      return { id: method, label: "Authenticator app", description: "Use an authenticator app (like Google Authenticator) to get your codes." };
    case "EMAIL":
      return { id: method, label: "Email", description: `Get a code by email at ${maskEmail(account.email)}.` };
    case "FIDO2":
      return { id: method, label: "Passkey", description: "Use your fingerprint, face, PIN or a security key." };
    case "SMS":
      return { id: method, label: "Text message", description: "Get a code by text message." };
  }
}

const expiry = () => Date.now() + MFA_TTL_MS;

async function qrDataUrl(keyUri: string): Promise<string> {
  const svg = await QRCode.toString(keyUri, { type: "svg", margin: 1, width: 192 });
  return `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;
}

function secretOf(keyUri: string): string {
  try {
    return new URL(keyUri).searchParams.get("secret") ?? "";
  } catch {
    return "";
  }
}

// The one place a transaction turns into what the browser sees, so a retry shows the same screen.
async function viewOf(tx: MfaTransaction, error?: string): Promise<MfaView> {
  const canSwitch = (tx.devices?.length ?? 0) > 1;
  switch (tx.step) {
    case "select":
      return { step: "select", devices: tx.devices, error };
    case "method":
      return { step: "method", methods: (tx.offered ?? []).map((m) => methodChoice(m, tx.account)), optional: tx.optional, prompt: tx.prompt, error };
    case "totp":
      return {
        step: "totp",
        prompt: tx.prompt,
        totp: tx.totpKeyUri ? { qr: await qrDataUrl(tx.totpKeyUri), secret: secretOf(tx.totpKeyUri) } : undefined,
        error,
      };
    case "passkey":
      return { step: "passkey", prompt: tx.prompt, passkey: tx.passkeyOptions ? { options: tx.passkeyOptions } : undefined, canSwitch, error };
    case "passkey-setup":
      return { step: "passkey-setup", prompt: tx.prompt, passkey: tx.passkeyOptions ? { options: tx.passkeyOptions } : undefined, error };
    case "otp":
      return { step: "otp", prompt: tx.prompt, canSwitch, error };
    default:
      return { step: tx.step, prompt: tx.prompt, error };
  }
}

async function show(tx: MfaTransaction, error?: string): Promise<FlowResult> {
  return { done: false, view: await viewOf(tx, error), transaction: tx };
}

function expired(error: string): FlowResult {
  return { done: false, view: { step: "expired", error }, transaction: null };
}

// ---- sign-in ----

// Once a device is selected, PingOne asks for either a typed code or a passkey assertion.
function afterSelect(tx: MfaTransaction, auth: api.DeviceAuthentication, choice: MfaDeviceChoice): Promise<FlowResult> | null {
  if (auth.status === "OTP_REQUIRED") return show({ ...tx, step: "otp", prompt: choice.prompt, passkeyOptions: undefined });
  if (auth.status === "ASSERTION_REQUIRED" && auth.requestOptions) {
    return show({ ...tx, step: "passkey", prompt: choice.prompt, passkeyOptions: auth.requestOptions });
  }
  return null;
}

// Call right after the password check succeeded.
export async function beginMfa(account: Account, ctx: MfaContext): Promise<FlowResult> {
  const devices = await api.listActiveDevices(account.id);
  if (devices.length === 0) return startSetup(account, ctx);

  let auth = await api.beginDeviceAuthentication(account.id);
  if (auth.status === "COMPLETED") return { done: true, account }; // the MFA policy decided no further step is needed

  const choices = devices.map(describeDevice);
  const picked = auth.status === "OTP_REQUIRED" || auth.status === "ASSERTION_REQUIRED";
  const base = { account, rpId: ctx.rpId, deviceAuthId: auth.id, expiresAt: expiry() };

  if (choices.length === 1) {
    // Only one way to verify, so there is nothing to choose.
    if (!picked) auth = await api.selectDevice(auth.id, devices[0].id);
    const step = afterSelect({ ...base, step: "otp", deviceAuthId: auth.id }, auth, choices[0]);
    if (!step) throw new MfaFlowError("Your account's verification method can't be used on this page.");
    return step;
  }

  // Two or more: the person decides, even when PingOne already picked a default and started on it.
  if (!picked && auth.status !== "DEVICE_SELECTION_REQUIRED") {
    throw new MfaFlowError("Your account's verification method can't be used on this page.");
  }
  return show({
    ...base,
    step: "select",
    devices: choices,
    selectedDeviceId: picked ? auth.selectedDeviceId : undefined,
    selectedStatus: picked ? auth.status : undefined,
    passkeyOptions: picked ? auth.requestOptions : undefined,
  });
}

async function chooseDevice(tx: MfaTransaction, deviceId: string): Promise<FlowResult> {
  const choice = tx.devices?.find((d) => d.id === deviceId);
  if (tx.step !== "select" || !tx.deviceAuthId || !choice) return show(tx, tx.step === "select" ? "Pick one of the options below." : undefined);

  // PingOne already picked (and started on) one device; choosing it again needs no new request and
  // no second code. Any other choice, or a return from "use a different method", is selected first.
  const alreadyStarted = deviceId === tx.selectedDeviceId && tx.selectedStatus;
  const auth: api.DeviceAuthentication = alreadyStarted
    ? { id: tx.deviceAuthId, status: tx.selectedStatus!, devices: [], requestOptions: tx.passkeyOptions }
    : await api.selectDevice(tx.deviceAuthId, deviceId);

  const next = afterSelect({ ...tx, selectedDeviceId: undefined, selectedStatus: undefined }, auth, choice);
  return next ?? show(tx, "That option can't be used on this page. Pick another.");
}

// "Use a different method": back to the list. Nothing is started on PingOne until another one is picked.
async function switchMethod(tx: MfaTransaction): Promise<FlowResult> {
  if ((tx.step !== "otp" && tx.step !== "passkey") || (tx.devices?.length ?? 0) < 2) return show(tx);
  return show({ ...tx, step: "select", prompt: undefined, passkeyOptions: undefined, selectedDeviceId: undefined, selectedStatus: undefined });
}

// ---- set-up ----

async function startSetup(account: Account, ctx: MfaContext): Promise<FlowResult> {
  let methods = await api.enrollmentMethods();
  if (!account.email) methods = methods.filter((m) => m !== "EMAIL");
  if (methods.length === 0) throw new MfaFlowError("No verification method is available for your account. Ask an administrator.");

  const tx: MfaTransaction = {
    account,
    rpId: ctx.rpId,
    step: "method",
    prompt: "Choose how you'd like to verify it's you when you sign in.",
    methods,
    offered: methods,
    enrolled: [],
    expiresAt: expiry(),
  };
  return methods.length === 1 ? beginMethod(tx, methods[0]) : show(tx);
}

async function beginMethod(tx: MfaTransaction, method: EnrollMethod): Promise<FlowResult> {
  const { account } = tx;
  switch (method) {
    case "EMAIL": {
      const { id } = await api.createEmailDevice(account.id, account.email);
      return show({ ...tx, step: "enroll", pendingMethod: method, enrollDeviceId: id, prompt: `We sent a code to ${maskEmail(account.email)}.` });
    }
    case "SMS":
      return show({ ...tx, step: "phone", pendingMethod: method, prompt: "Enter the mobile number that should get your codes." });
    case "TOTP": {
      const { id, keyUri } = await api.createTotpDevice(account.id);
      return show({
        ...tx,
        step: "totp",
        pendingMethod: method,
        enrollDeviceId: id,
        totpKeyUri: keyUri,
        prompt: "Scan this QR code with an authenticator app, then enter the code the app shows.",
      });
    }
    case "FIDO2": {
      const { id, options } = await api.createFido2Device(account.id, { id: tx.rpId, name: RP_NAME });
      return show({
        ...tx,
        step: "passkey-setup",
        pendingMethod: method,
        enrollDeviceId: id,
        passkeyOptions: options,
        prompt: "Your device will ask you to confirm with a fingerprint, face, PIN or security key.",
      });
    }
  }
}

async function chooseMethod(tx: MfaTransaction, raw: string): Promise<FlowResult> {
  if (tx.step !== "method") return show(tx);
  const method = tx.offered?.find((m) => m === raw);
  return method ? beginMethod(tx, method) : show(tx, "Pick one of the options below.");
}

async function submitPhone(tx: MfaTransaction, raw: string): Promise<FlowResult> {
  if (tx.step !== "phone") return show(tx);
  const phone = raw.trim();
  const invalid = "That number doesn't look right. Include the country code, like +1 512 520 1234.";
  if (!/^\+?[0-9 ().-]{7,20}$/.test(phone) || phone.replace(/\D/g, "").length < 7) return show(tx, invalid);

  const device = await api.createSmsDevice(tx.account.id, phone.startsWith("+") ? phone : `+${phone}`);
  if (device === "invalid") return show(tx, invalid);
  return show({ ...tx, step: "enroll", enrollDeviceId: device.id, prompt: `We texted a code to ${maskPhone(phone)}.` });
}

// The method just proved itself. Offer the remaining ones as an optional extra, or finish.
async function afterSetup(tx: MfaTransaction): Promise<FlowResult> {
  const enrolled = [...(tx.enrolled ?? []), ...(tx.pendingMethod ? [tx.pendingMethod] : [])];
  const remaining = (tx.methods ?? []).filter((m) => !enrolled.includes(m));
  if (remaining.length === 0) return { done: true, account: tx.account };

  return show({
    account: tx.account,
    rpId: tx.rpId,
    step: "method",
    optional: true,
    prompt: "You're all set. Want another way to verify, in case you can't use this one?",
    methods: tx.methods,
    offered: remaining,
    enrolled,
    expiresAt: expiry(),
  });
}

// ---- the code step, for both sign-in and set-up ----

async function submitCode(tx: MfaTransaction, rawCode: string): Promise<FlowResult> {
  const code = rawCode.replace(/\s+/g, "");
  if (tx.step !== "otp" && tx.step !== "enroll" && tx.step !== "totp") return show(tx);
  if (!code) return show(tx, "Enter the code.");
  const wrong = "That code didn't work. Check it and try again.";

  if (tx.step === "otp") {
    if (!tx.deviceAuthId) return expired("Your sign-in timed out. Start again.");
    const result = await api.checkOtp(tx.deviceAuthId, code);
    if (result === "ok") return { done: true, account: tx.account };
    if (result === "failed") return expired("Too many wrong codes. Start again.");
    return show(tx, wrong);
  }

  if (!tx.enrollDeviceId) return expired("Your sign-in timed out. Start again.");
  return (await api.activateDevice(tx.account.id, tx.enrollDeviceId, code)) === "ok" ? afterSetup(tx) : show(tx, wrong);
}

// ---- the passkey step, for both sign-in and set-up ----
// The browser did the WebAuthn part; `credential` is its response as JSON text, `origin` the page's origin.

async function submitPasskey(tx: MfaTransaction, credential: string, origin: string): Promise<FlowResult> {
  if (tx.step !== "passkey" && tx.step !== "passkey-setup") return show(tx);
  if (!credential || !/^https?:\/\/[^\s/]+$/.test(origin)) return show(tx, "Something went wrong with the passkey. Try again.");

  if (tx.step === "passkey") {
    if (!tx.deviceAuthId) return expired("Your sign-in timed out. Start again.");
    const result = await api.checkAssertion(tx.deviceAuthId, origin, credential);
    if (result === "ok") return { done: true, account: tx.account };
    if (result === "failed") return expired("Too many failed attempts. Start again.");
    return show(tx, "That passkey didn't work. Try again" + ((tx.devices?.length ?? 0) > 1 ? ", or use a different method." : "."));
  }

  if (!tx.enrollDeviceId) return expired("Your sign-in timed out. Start again.");
  return (await api.activatePasskey(tx.account.id, tx.enrollDeviceId, origin, credential)) === "ok"
    ? afterSetup(tx)
    : show(tx, "We couldn't save that passkey. Try again.");
}

export async function advance(tx: MfaTransaction, action: MfaAction): Promise<FlowResult> {
  switch (action.type) {
    case "select":
      return chooseDevice(tx, action.deviceId);
    case "back":
      return switchMethod(tx);
    case "method":
      return chooseMethod(tx, action.method);
    case "phone":
      return submitPhone(tx, action.phone);
    case "verify":
      return submitCode(tx, action.code);
    case "passkey":
      return submitPasskey(tx, action.credential, action.origin);
    case "skip":
      return tx.step === "method" && tx.optional ? { done: true, account: tx.account } : show(tx);
  }
}
