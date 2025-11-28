/**
 * make_x_signature_payment
 * ----------------------------------------------------
 * Python:
 *   key_str = f"{X_API_BASE_SECRET};{sig}#ae-hei...;POST;{path};{sig}"
 *   msg = f"{access_token};{token_payment};{sig};{payment_for};{payment_method};{package_code};"
 */

import { hmacSHA512 } from "../sha_utils.js";

export async function make_x_signature_payment(
  config,
  access_token,
  sig_time_sec,
  package_code,
  token_payment,
  payment_method,
  payment_for,
  path
) {
  const keyStr = `${config.X_API_BASE_SECRET};${sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;POST;${path};${sig_time_sec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const message = new TextEncoder().encode(
    `${access_token};${token_payment};${sig_time_sec};${payment_for};${payment_method};${package_code};`
  );

  return await hmacSHA512(keyBytes, message);
}
