/**
 * BOUNTY SIGNATURE
 * ----------------------------------------------------
 * Python:
 *   key = f"{SECRET};{access};{sig}#ae-hei...;POST;api/v8/personalization/bounties-exchange;{sig}"
 *   msg = f"{access_token};{token_payment};{sig};{package_code};"
 */

import { hmacSHA512 } from "../sha_utils.js";

export async function make_x_signature_bounty(
  config,
  access_token,
  sig_time_sec,
  package_code,
  token_payment
) {
  const path = "api/v8/personalization/bounties-exchange";

  const keyStr = `${config.X_API_BASE_SECRET};${access_token};${sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;POST;${path};${sig_time_sec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const message = new TextEncoder().encode(
    `${access_token};${token_payment};${sig_time_sec};${package_code};`
  );

  return await hmacSHA512(keyBytes, message);
}
