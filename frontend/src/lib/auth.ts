const KEY = "homepulse-logged-in";

export const isLoggedIn = () => sessionStorage.getItem(KEY) === "1";

export const login = () => sessionStorage.setItem(KEY, "1");

export const logout = () => sessionStorage.removeItem(KEY);

/* ------------------------------------------------------------------------- *
 *  SECURE build — a REAL login (contrast with the trivial flag above, which
 *  the insecure build deliberately uses). Credentials are validated by
 *  hashing the password (Web Crypto SHA-256) and comparing to a stored digest;
 *  the dashboard only mounts — and only connects to the broker — after success.
 *
 *  Demo credentials:  admin / homepulse-secure-2026
 *  (To change: sha256 the new password and replace SECURE_PW_SHA256.)
 * ------------------------------------------------------------------------- */
const SECURE_KEY = "homepulse-secure-authed";
const SECURE_USER = "admin";
const SECURE_PW_SHA256 =
  "c54c093f5bb1eb539a8fbfe72dcb5aa44788254047cc32e8cc282990191eb3bf";

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const isSecurelyAuthed = () => sessionStorage.getItem(SECURE_KEY) === "1";

export const secureLogout = () => sessionStorage.removeItem(SECURE_KEY);

/** Returns true and establishes a session on valid credentials, else false. */
export async function secureLogin(username: string, password: string): Promise<boolean> {
  const ok = username === SECURE_USER && (await sha256Hex(password)) === SECURE_PW_SHA256;
  if (ok) sessionStorage.setItem(SECURE_KEY, "1");
  return ok;
}
