// Base64url <-> ArrayBuffer helpers for WebAuthn, which encodes binary
// fields (challenge, credential IDs, etc.) as base64url strings in JSON
// but the browser's navigator.credentials API needs real ArrayBuffers.

export function base64urlToBuffer(value: string): ArrayBuffer {
  const padLength = (4 - (value.length % 4)) % 4;
  const padded = (value + "=".repeat(padLength)).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
