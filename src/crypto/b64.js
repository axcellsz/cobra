/**
 * Base64 URL-safe encode/decode 
 * untuk menyamai Python urlsafe_b64encode
 */

export function b64urlEncode(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(b64url) {
  let str = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";

  const raw = atob(str);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
