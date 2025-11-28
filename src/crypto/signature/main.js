/**
 * make_x_signature
 * -----------------------------------------------
 * Python:
 *   key_str = f"{X_API_BASE_SECRET};{id_token};{method};{path};{sig_time_sec}"
 *   HMAC_SHA512( key_bytes, msg="{id_token};{sig_time_sec};" )
 */

import { hmacSHA512 } from "../sha_utils.js";

export async function make_x_signature(config, id_token, method, path, sig_time_sec) {
  const keyStr = `${config.X_API_BASE_SECRET};${id_token};${method};${path};${sig_time_sec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const message = new TextEncoder().encode(`${id_token};${sig_time_sec};`);

  return await hmacSHA512(keyBytes, message);
}
