/**
 * BOUNTY ALLOTMENT SIGNATURE
 * ----------------------------------------------------
 * Python:
 *   key = f"{SECRET};{sig}#ae-hei...;{dest};POST;{path};{sig}"
 *   msg = f"{token_confirmation};{sig};{dest};{package_code};"
 */

import { hmacSHA512 } from "../sha_utils.js";

export async function make_x_signature_bounty_allotment(
  config,
  sig_time_sec,
  package_code,
  token_confirmation,
  path,
  destination_msisdn
) {
  const keyStr = `${config.X_API_BASE_SECRET};${sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;${destination_msisdn};POST;${path};${sig_time_sec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const message = new TextEncoder().encode(
    `${token_confirmation};${sig_time_sec};${destination_msisdn};${package_code};`
  );

  return await hmacSHA512(keyBytes, message);
}
