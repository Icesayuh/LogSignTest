import type { EnrollMethod } from "./mfa-types";
import { call, readConfig, type ApiResult } from "./pingone";

// PingOne MFA over its APIs (server-only; uses the worker app's token):
//  - devices and policies live on the Management API: /v1/environments/{env}/...
//  - the sign-in challenge lives on the auth host:    https://auth.pingone.<region>/{env}/deviceAuthentications
// The worker app needs these permissions: mfa:authenticate:device, mfa:create:device, mfa:update:device,
// mfa:read:deviceAuthenticationPolicy (and Identity Data Admin for users and devices).

export type MfaDevice = { id: string; type: string; status?: string; email?: string; phone?: string };

// Device types this page can verify: codes typed in, or a passkey. Push and the like are not handled.
const SUPPORTED_DEVICE_TYPES = ["EMAIL", "SMS", "VOICE", "TOTP", "FIDO2"];
export const isSupportedDevice = (device: MfaDevice) => SUPPORTED_DEVICE_TYPES.includes(device.type);

export type DeviceAuthentication = {
  id: string;
  status: string;
  devices: MfaDevice[];
  selectedDeviceId?: string;
  requestOptions?: string; // status ASSERTION_REQUIRED: WebAuthn request options (JSON) for the selected passkey
};

// Auth/permission problems and PingOne outages are real errors, not "wrong code".
const isHardFailure = (r: ApiResult) => r.status === 401 || r.status === 403 || r.status >= 500;

function failure(what: string, r: ApiResult): Error {
  const code = r.data?.code ? ` ${r.data.code}` : "";
  const hint = r.status === 403 ? " Check the worker app's roles and permissions (see .env.example)." : "";
  return new Error(`${what} failed (${r.status}${code}).${hint}`);
}

// PingOne hands WebAuthn options over as a JSON string (the docs' prose also calls it an object); accept both.
const asJsonString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : value && typeof value === "object" ? JSON.stringify(value) : undefined;

function toDeviceAuthentication(data: any): DeviceAuthentication {
  return {
    id: data?.id,
    status: data?.status,
    devices: data?._embedded?.devices ?? [],
    selectedDeviceId: data?.selectedDevice?.id,
    requestOptions: asJsonString(data?.publicKeyCredentialRequestOptions),
  };
}

// ---- which methods can be set up ----

const ENROLL_METHODS: EnrollMethod[] = ["TOTP", "EMAIL", "FIDO2", "SMS"];

// The methods the MFA policy allows (and this page can set up). PINGONE_MFA_METHODS overrides the
// policy, e.g. "TOTP,EMAIL" to leave passkeys out. If the policy can't be read, email alone is
// offered rather than blocking sign-up.
export async function enrollmentMethods(): Promise<EnrollMethod[]> {
  const override = process.env.PINGONE_MFA_METHODS;
  if (override) {
    const wanted = override.split(",").map((m) => m.trim().toUpperCase());
    return ENROLL_METHODS.filter((m) => wanted.includes(m));
  }

  try {
    const policyId = process.env.PINGONE_MFA_POLICY_ID;
    const r = await call(readConfig(), policyId ? `/deviceAuthenticationPolicies/${encodeURIComponent(policyId)}` : "/deviceAuthenticationPolicies");
    if (!r.ok) throw failure("Reading the MFA policy", r);
    const policy = policyId ? r.data : (r.data?._embedded?.deviceAuthenticationPolicies ?? []).find((p: any) => p?.default);
    if (!policy) throw new Error("No default MFA policy was found.");
    return ENROLL_METHODS.filter((m) => policy[m.toLowerCase()]?.enabled === true);
  } catch (error) {
    console.warn("Could not read the MFA policy, so only email is offered:", error);
    return ["EMAIL"];
  }
}

// ---- devices ----

export async function listActiveDevices(userId: string): Promise<MfaDevice[]> {
  const r = await call(readConfig(), `/users/${encodeURIComponent(userId)}/devices`);
  if (!r.ok) throw failure("Listing MFA devices", r);
  const devices: MfaDevice[] = r.data?._embedded?.devices ?? [];
  return devices.filter((device) => device.status === "ACTIVE" && isSupportedDevice(device));
}

async function createDevice(userId: string, body: Record<string, unknown>): Promise<ApiResult> {
  return call(readConfig(), `/users/${encodeURIComponent(userId)}/devices`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Email and text message devices are created as ACTIVATION_REQUIRED, which makes PingOne send the
// person a code; typing it back proves they have the device (see activateDevice). Authenticator app
// and passkey devices start out needing activation on their own.
export async function createEmailDevice(userId: string, email: string): Promise<{ id: string }> {
  const r = await createDevice(userId, { type: "EMAIL", email, status: "ACTIVATION_REQUIRED" });
  if (!r.ok || !r.data?.id) throw failure("Creating the email MFA device", r);
  return { id: r.data.id };
}

// "invalid" when PingOne rejects the number (bad format, or text messages not enabled).
export async function createSmsDevice(userId: string, phone: string): Promise<{ id: string } | "invalid"> {
  const r = await createDevice(userId, { type: "SMS", phone, status: "ACTIVATION_REQUIRED" });
  if (isHardFailure(r)) throw failure("Creating the text message MFA device", r);
  if (r.status === 400) {
    console.warn("PingOne rejected the SMS device:", JSON.stringify(r.data?.details ?? r.data?.code));
    return "invalid";
  }
  if (!r.ok || !r.data?.id) throw failure("Creating the text message MFA device", r);
  return { id: r.data.id };
}

// The secret and key URI come back only when the device is created, so they are shown right away.
export async function createTotpDevice(userId: string): Promise<{ id: string; keyUri: string }> {
  const r = await createDevice(userId, { type: "TOTP" });
  if (!r.ok || !r.data?.id || typeof r.data?.keyUri !== "string") throw failure("Creating the authenticator app device", r);
  return { id: r.data.id, keyUri: r.data.keyUri };
}

// The relying party must be the site the passkey will be used on: its host name is the passkey's
// scope, and the browser refuses to create one for any other site.
export async function createFido2Device(userId: string, rp: { id: string; name: string }): Promise<{ id: string; options: string }> {
  const policyId = process.env.PINGONE_MFA_POLICY_ID;
  const r = await createDevice(userId, { type: "FIDO2", rp, ...(policyId ? { policy: { id: policyId } } : {}) });
  const options = asJsonString(r.data?.publicKeyCredentialCreationOptions);
  if (!r.ok || !r.data?.id || !options) throw failure("Creating the passkey device", r);
  return { id: r.data.id, options };
}

async function activate(userId: string, deviceId: string, payload: Record<string, unknown>): Promise<"ok" | "wrong"> {
  const r = await call(readConfig(), `/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(deviceId)}`, {
    method: "POST",
    headers: { "Content-Type": "application/vnd.pingidentity.device.activate+json" },
    body: JSON.stringify(payload),
  });
  if (isHardFailure(r)) throw failure("Activating the MFA device", r);
  return r.ok ? "ok" : "wrong";
}

export const activateDevice = (userId: string, deviceId: string, otp: string) => activate(userId, deviceId, { otp });

// `attestation` is the browser's new-passkey response as a JSON string, `origin` the page's origin.
export const activatePasskey = (userId: string, deviceId: string, origin: string, attestation: string) =>
  activate(userId, deviceId, { origin, attestation });

// ---- sign-in challenge ----

export async function beginDeviceAuthentication(userId: string): Promise<DeviceAuthentication> {
  const policyId = process.env.PINGONE_MFA_POLICY_ID;
  const r = await call(readConfig(), "/deviceAuthentications", {
    auth: true,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: { id: userId }, ...(policyId ? { policy: { id: policyId } } : {}) }),
  });
  if (!r.ok) throw failure("Starting MFA", r);
  return toDeviceAuthentication(r.data);
}

export async function selectDevice(deviceAuthenticationId: string, deviceId: string): Promise<DeviceAuthentication> {
  const r = await call(readConfig(), `/deviceAuthentications/${encodeURIComponent(deviceAuthenticationId)}`, {
    auth: true,
    method: "POST",
    headers: { "Content-Type": "application/vnd.pingidentity.device.select+json" },
    body: JSON.stringify({ device: { id: deviceId } }),
  });
  if (!r.ok) throw failure("Selecting the MFA device", r);
  return toDeviceAuthentication(r.data);
}

type CheckResult = "ok" | "wrong" | "failed";

async function check(deviceAuthenticationId: string, contentType: string, payload: Record<string, unknown>): Promise<CheckResult> {
  const r = await call(readConfig(), `/deviceAuthentications/${encodeURIComponent(deviceAuthenticationId)}`, {
    auth: true,
    method: "POST",
    headers: { "Content-Type": contentType },
    body: JSON.stringify(payload),
  });
  if (isHardFailure(r)) throw failure("Checking the MFA response", r);
  // Fail closed: only an explicit COMPLETED signs anyone in. PingOne's docs show that for codes but
  // not what a wrong code (or a wrong assertion) returns, so everything else counts as wrong.
  if (r.ok && r.data?.status === "COMPLETED") return "ok";
  if (r.data?.status === "FAILED") return "failed";
  return "wrong";
}

export const checkOtp = (deviceAuthenticationId: string, otp: string) =>
  check(deviceAuthenticationId, "application/vnd.pingidentity.otp.check+json", { otp });

// `assertion` is the browser's passkey response as a JSON string, `origin` the page's origin.
export const checkAssertion = (deviceAuthenticationId: string, origin: string, assertion: string) =>
  check(deviceAuthenticationId, "application/vnd.pingidentity.assertion.check+json", { origin, assertion, compatibility: "FULL" });
