/**
 * LOYALTY SIGNATURE
 * ----------------------------------------------------
 * Python:
 *   key = f"{SECRET};{sig}#ae-hei...;POST;{path};{sig}"
 *   msg = f"{token_confirmation};{sig};{package_code};"
 */

import { hmacSHA512 } from "../sha_utils.js";

export async function make_x_signature_loyalty(
  config,
  sig_time_sec,
  package_code,
  token_confirmation,
  path
) {
  const keyStr = `${config.X_API_BASE_SECRET};${sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;POST;${path};${sig_time_sec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const message = new TextEncoder().encode(
    `${token_confirmation};${sig_time_sec};${package_code};`
  );

  return await hmacSHA512(keyBytes, message);
}
