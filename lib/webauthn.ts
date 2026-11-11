// Browser-only helpers for passkeys (WebAuthn). PingOne sends the options as JSON with binary values
// encoded as text; the browser wants real byte buffers, and PingOne wants the result back as JSON text.

// PingOne's examples use standard base64; accept the URL-safe variant too.
function fromBase64(text: string): ArrayBuffer {
  const standard = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(standard + "=".repeat((4 - (standard.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export const passkeysSupported = () => typeof window !== "undefined" && "credentials" in navigator && "PublicKeyCredential" in window;

// Creates a passkey on this device. Returns the "attestation" PingOne asks for.
export async function createPasskey(optionsJson: string): Promise<string> {
  const options = JSON.parse(optionsJson);
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: fromBase64(options.challenge),
    user: { ...options.user, id: fromBase64(options.user.id) },
    excludeCredentials: (options.excludeCredentials ?? []).map((c: { id: string }) => ({ ...c, id: fromBase64(c.id) })),
  };

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was created.");
  const response = credential.response as AuthenticatorAttestationResponse;

  return JSON.stringify({
    id: credential.id,
    type: credential.type,
    rawId: toBase64(credential.rawId),
    response: {
      clientDataJSON: toBase64(response.clientDataJSON),
      attestationObject: toBase64(response.attestationObject),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  });
}

// Signs the sign-in challenge with an existing passkey. Returns the "assertion" PingOne asks for.
export async function signWithPasskey(optionsJson: string): Promise<string> {
  const options = JSON.parse(optionsJson);
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...options,
    challenge: fromBase64(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((c: { id: string }) => ({ ...c, id: fromBase64(c.id) })),
  };

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was used.");
  const response = credential.response as AuthenticatorAssertionResponse;

  return JSON.stringify({
    id: credential.id,
    type: credential.type,
    rawId: toBase64(credential.rawId),
    response: {
      clientDataJSON: toBase64(response.clientDataJSON),
      authenticatorData: toBase64(response.authenticatorData),
      signature: toBase64(response.signature),
      userHandle: response.userHandle ? toBase64(response.userHandle) : null,
    },
  });
}
