import { call, readConfig, type ApiResult } from "./pingone";

// PingOne MFA over its APIs (server-only; uses the worker app's token):
//  - devices live on the Management API:      /v1/environments/{env}/users/{user}/devices
//  - the sign-in challenge lives on auth host: https://auth.pingone.<region>/{env}/deviceAuthentications
// Needs the worker app to hold the permission mfa:authenticate:device (and Identity Data Admin for devices).

export type MfaDevice = { id: string; type: string; status?: string; email?: string; phone?: string };

// Device types that can be answered by typing a code. Push, FIDO2 and the like are not handled here.
const OTP_DEVICE_TYPES = ["EMAIL", "SMS", "VOICE", "TOTP"];
export const isOtpDevice = (device: MfaDevice) => OTP_DEVICE_TYPES.includes(device.type);

export type DeviceAuthentication = {
  id: string;
  status: string;
  devices: MfaDevice[];
  selectedDeviceId?: string;
};

// Auth/permission problems and PingOne outages are real errors, not "wrong code".
const isHardFailure = (r: ApiResult) => r.status === 401 || r.status === 403 || r.status >= 500;

function failure(what: string, r: ApiResult): Error {
  const code = r.data?.code ? ` ${r.data.code}` : "";
  const hint = r.status === 403 ? " Does the worker app have the permission mfa:authenticate:device and the Identity Data Admin role?" : "";
  return new Error(`${what} failed (${r.status}${code}).${hint}`);
}

function toDeviceAuthentication(data: any): DeviceAuthentication {
  return {
    id: data?.id,
    status: data?.status,
    devices: data?._embedded?.devices ?? [],
    selectedDeviceId: data?.selectedDevice?.id,
  };
}

export async function listActiveDevices(userId: string): Promise<MfaDevice[]> {
  const r = await call(readConfig(), `/users/${encodeURIComponent(userId)}/devices`);
  if (!r.ok) throw failure("Listing MFA devices", r);
  const devices: MfaDevice[] = r.data?._embedded?.devices ?? [];
  return devices.filter((device) => device.status === "ACTIVE" && isOtpDevice(device));
}

// Creates an email device in ACTIVATION_REQUIRED state; PingOne emails the user a code to activate it.
export async function createEmailDevice(userId: string, email: string): Promise<{ id: string }> {
  const r = await call(readConfig(), `/users/${encodeURIComponent(userId)}/devices`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "EMAIL", email, status: "ACTIVATION_REQUIRED" }),
  });
  if (!r.ok || !r.data?.id) throw failure("Creating the email MFA device", r);
  return { id: r.data.id };
}

export async function activateDevice(userId: string, deviceId: string, otp: string): Promise<"ok" | "wrong"> {
  const r = await call(readConfig(), `/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(deviceId)}`, {
    method: "POST",
    headers: { "Content-Type": "application/vnd.pingidentity.device.activate+json" },
    body: JSON.stringify({ otp }),
  });
  if (isHardFailure(r)) throw failure("Activating the MFA device", r);
  return r.ok ? "ok" : "wrong";
}

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

// PingOne's docs describe the success case (200, status COMPLETED) but not what a wrong code
// returns, so anything that isn't a hard failure and isn't COMPLETED counts as a wrong code.
export async function checkOtp(deviceAuthenticationId: string, otp: string): Promise<"ok" | "wrong" | "failed"> {
  const r = await call(readConfig(), `/deviceAuthentications/${encodeURIComponent(deviceAuthenticationId)}`, {
    auth: true,
    method: "POST",
    headers: { "Content-Type": "application/vnd.pingidentity.otp.check+json" },
    body: JSON.stringify({ otp }),
  });
  if (isHardFailure(r)) throw failure("Checking the MFA code", r);
  if (r.ok && r.data?.status === "COMPLETED") return "ok";
  if (r.data?.status === "FAILED") return "failed";
  return "wrong";
}
