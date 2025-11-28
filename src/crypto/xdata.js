/**
 * ===============================
 *  XDATA ENCRYPT / DECRYPT
 *  (Port dari crypto_helper.py)
 * ===============================
 *
 *  Python:
 *     iv = sha256(str(xtime))[:16]   # 16 chars ASCII → 16 bytes
 *     AES-CBC dengan key XDATA_KEY
 *     xdata = base64_urlsafe( AES.encrypt(pad(json)) )
 *
 *  Worker:
 *     WebCrypto AES-CBC (native)
 */

import { sha256hex } from "./sha_utils.js";
import { b64urlEncode, b64urlDecode } from "./b64.js";

// -----------------------------------------------------------------------------
// derive_iv : menghasilkan IV 16-byte dari SHA256(xtime_ms)
// -----------------------------------------------------------------------------
export function deriveIV(xtime_ms) {
  // Hasil sha256 = hex string 64 chars → ambil 16 chars pertama
  const hex = sha256hex(String(xtime_ms)).slice(0, 16);

  // ASCII ke Uint8Array
  const bytes = new Uint8Array(
    hex.split("").map((c) => c.charCodeAt(0))
  );

  return bytes;
}

// -----------------------------------------------------------------------------
// ENCRYPT XDATA (AES-256-CBC)
// -----------------------------------------------------------------------------
export async function encryptXData(plaintext, xtime_ms, config) {
  const iv = deriveIV(xtime_ms);

  // Import XDATA key sebagai raw bytes
  const keyBytes = hexToBytes(config.XDATA_KEY); // 32-byte HEX
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );

  // Encode plaintext
  const data = new TextEncoder().encode(plaintext);

  // AES-CBC encrypt
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    data
  );

  // URL-safe Base64
  return b64urlEncode(new Uint8Array(encrypted));
}

// -----------------------------------------------------------------------------
// DECRYPT XDATA (AES-256-CBC)
// -----------------------------------------------------------------------------
export async function decryptXData(xdata, xtime_ms, config) {
  const iv = deriveIV(xtime_ms);

  const keyBytes = hexToBytes(config.XDATA_KEY);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  const encryptedBytes = b64urlDecode(xdata);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    key,
    encryptedBytes
  );

  return new TextDecoder().decode(decrypted);
}

// -----------------------------------------------------------------------------
// Helper: hex string → Uint8Array
// -----------------------------------------------------------------------------
export function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}
