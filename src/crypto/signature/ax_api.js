/**
 * AX API SIGNATURE (untuk CIAM OTP)
 * ----------------------------------------------------
 * Python:
 *   preimage = f"{ts}password{type}{contact}{code}openid"
 *   HMAC-SHA256( AX_API_SIG_KEY, preimage )
 */

import { hmacSHA256 } from "../sha_utils.js";

export async function make_ax_api_signature(config, ts, contact, code, contactType) {
  const preimage = `${ts}password${contactType}${contact}${code}openid`;

  const keyBytes = hexToBytes(config.AX_API_SIG_KEY);
  const message = new TextEncoder().encode(preimage);

  return await hmacSHA256(keyBytes, message);
}

// HEX util
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}
