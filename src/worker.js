// ===============================
//  Cloudflare Worker - MyXL (Cobra)
//  FIXED VERSION - TIMESTAMP VALID
//  AUTO LOAD PROFILE
// ===============================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // API ROUTES
    if (url.pathname === "/api/get-otp" && request.method === "POST") {
      return handleGetOtp(request, env);
    }

    if (url.pathname === "/api/submit-otp" && request.method === "POST") {
      return handleSubmitOtp(request, env);
    }

    if (url.pathname === "/api/profile" && request.method === "POST") {
      return handleProfile(request, env);
    }

    // STATIC FILES FROM KV
    return handleStatic(url, env);
  },
};

/* ===========================
 * STATIC FILE HANDLER
 * =========================== */

async function handleStatic(url, env) {
  let key = url.pathname.replace(/^\/+/, "");
  if (!key) key = "index.html";

  const obj = await env.Pages2.get(key, { type: "stream" });
  if (!obj) return new Response("Not found", { status: 404 });

  return new Response(obj, {
    headers: { "content-type": contentTypeFromPath(key) },
  });
}

function contentTypeFromPath(path) {
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (path.endsWith(".css")) return "text/css; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  return "text/plain; charset=utf-8";
}

/* ===========================
 * API: GET OTP
 * =========================== */

async function handleGetOtp(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.msisdn)
    return json({ ok: false, message: "msisdn is required" }, 400);

  const msisdn = String(body.msisdn);
  if (!msisdn.startsWith("628") || msisdn.length > 14)
    return json({ ok: false, message: "Invalid msisdn" }, 400);

  const config = loadConfig(env);
  const axFp = await loadAxFp(env, config);
  const axDeviceId = await computeAxDeviceId(axFp);

  const url = config.BASE_CIAM_URL + "/realms/xl-ciam/auth/otp";

  const axRequestAt = javaLikeTimestampGmt7();
  const axRequestId = crypto.randomUUID();

  const params = new URLSearchParams({
    contact: msisdn,
    contactType: "SMS",
    alternateContact: "false",
  });

  const headers = {
    "Accept-Encoding": "gzip, deflate, br",
    Authorization: `Basic ${config.BASIC_AUTH}`,
    "Ax-Device-Id": axDeviceId,
    "Ax-Fingerprint": axFp,
    "Ax-Request-At": axRequestAt,
    "Ax-Request-Device": "samsung",
    "Ax-Request-Device-Model": "SM-N935F",
    "Ax-Request-Id": axRequestId,
    "Ax-Substype": "PREPAID",
    "Content-Type": "application/json",
    Host: config.BASE_CIAM_URL.replace("https://", ""),
    "User-Agent": config.UA,
  };

  const resp = await fetch(url + "?" + params.toString(), {
    method: "GET",
    headers,
  });

  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return json({ ok: false, message: "Invalid JSON", raw: text }, 502);
  }

  if (!data.subscriber_id)
    return json(
      { ok: false, message: data.error || "Subscriber ID missing", raw: data },
      400
    );

  await env.Pages2.put(`SUB_ID:${msisdn}`, data.subscriber_id);

  return json({ ok: true, subscriber_id: data.subscriber_id });
}

/* ===========================
 * API: SUBMIT OTP
 * =========================== */

async function handleSubmitOtp(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.msisdn || !body.otp)
    return json({ ok: false, message: "msisdn & otp required" }, 400);

  const msisdn = String(body.msisdn);
  const otp = String(body.otp);

  if (!msisdn.startsWith("628")) return json({ ok: false, message: "Invalid msisdn" }, 400);
  if (otp.length !== 6) return json({ ok: false, message: "OTP must be 6 digits" }, 400);

  const config = loadConfig(env);
  const axFp = await loadAxFp(env, config);
  const axDeviceId = await computeAxDeviceId(axFp);

  const url =
    config.BASE_CIAM_URL + "/realms/xl-ciam/protocol/openid-connect/token";

  const tsForSign = tsGmt7WithoutColon();
  const tsHeader = tsGmt7WithoutColon();

  const signature = await makeAxApiSignature(
    config,
    tsForSign,
    msisdn,
    otp,
    "SMS"
  );

  const payload = new URLSearchParams({
    contactType: "SMS",
    code: otp,
    grant_type: "password",
    contact: msisdn,
    scope: "openid",
  });

  const headers = {
    "Accept-Encoding": "gzip, deflate, br",
    Authorization: `Basic ${config.BASIC_AUTH}`,
    "Ax-Api-Signature": signature,
    "Ax-Device-Id": axDeviceId,
    "Ax-Fingerprint": axFp,
    "Ax-Request-At": tsHeader,
    "Ax-Request-Device": "samsung",
    "Ax-Request-Device-Model": "SM-N935F",
    "Ax-Request-Id": crypto.randomUUID(),
    "Ax-Substype": "PREPAID",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": config.UA,
  };

  const resp = await fetch(url, {
    method: "POST",
    headers,
    body: payload.toString(),
  });

  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return json({ ok: false, message: "Invalid JSON", raw: text }, 502);
  }

  if (data.error)
    return json(
      {
        ok: false,
        message: data.error_description || data.error,
        raw: data,
      },
      400
    );

  const tokens = {
    access_token: data.access_token,
    id_token: data.id_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in,
    token_type: data.token_type,
  };

  await addRefreshToken(env, msisdn, tokens);

  return json({ ok: true, tokens });
}

/* ===========================
 * API: PROFILE AUTO LOAD
 * =========================== */

async function handleProfile(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.access_token)
    return json({ ok: false, message: "access_token required" }, 400);

  const access_token = body.access_token;
  const config = loadConfig(env);

  const url =
    config.BASE_CIAM_URL +
    "/realms/xl-ciam/protocol/openid-connect/userinfo";

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "User-Agent": config.UA,
      Accept: "application/json",
    },
  });

  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return json({ ok: false, message: "Invalid JSON", raw: text }, 502);
  }

  if (!resp.ok || data.error)
    return json(
      {
        ok: false,
        message: data.error_description || data.error || "Gagal load profile",
        raw: data,
      },
      400
    );

  return json({ ok: true, profile: data });
}

/* ===========================
 * REFRESH TOKEN STORAGE
 * =========================== */

async function loadRefreshTokens(env) {
  const raw = await env.Pages2.get("REFRESH_TOKENS");
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function saveRefreshTokens(env, list) {
  await env.Pages2.put("REFRESH_TOKENS", JSON.stringify(list));
}

async function addRefreshToken(env, msisdn, tokens) {
  const number = Number(msisdn);
  const list = await loadRefreshTokens(env);
  let existing = list.find((x) => x.number === number);

  if (existing) existing.refresh_token = tokens.refresh_token;
  else
    list.push({
      number,
      subscriber_id: "",
      subscription_type: "",
      refresh_token: tokens.refresh_token,
    });

  await saveRefreshTokens(env, list);
  await env.Pages2.put("ACTIVE_NUMBER", String(number));
}

/* ===========================
 * FINGERPRINT & DEVICE ID
 * =========================== */

async function loadAxFp(env, config) {
  const existing = await env.Pages2.get("AX_FP");
  if (existing) return existing;

  const rand = () => Math.floor(Math.random() * 9000 + 1000);
  const plain =
    `samsung${rand()}|SM-N93${rand()}|en|720x1540|GMT07:00|192.169.69.69|1.0|Android 13|6281398370564`;

  const keyBytes = new TextEncoder().encode(config.AX_FP_KEY);
  const iv = new Uint8Array(16);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );

  const pt = new TextEncoder().encode(plain);
  const pad = 16 - (pt.length % 16 || 16);
  const padded = new Uint8Array(pt.length + pad);
  padded.set(pt);
  padded.fill(pad, pt.length);

  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded);

  let bin = "";
  for (const b of new Uint8Array(ct)) bin += String.fromCharCode(b);
  const b64 = btoa(bin);

  await env.Pages2.put("AX_FP", b64);
  return b64;
}

async function computeAxDeviceId(axFp) {
  const hashHex = await sha256hex(axFp);
  return hashHex.slice(0, 32);
}

/* ===========================
 * AX API SIGNATURE
 * =========================== */

async function makeAxApiSignature(config, ts, contact, code, type) {
  const pre = `${ts}password${type}${contact}${code}openid`;

  const keyBytes = new TextEncoder().encode(config.AX_API_SIG_KEY);
  const msgBytes = new TextEncoder().encode(pre);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);

  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/* ===========================
 * TIMESTAMP SYSTEM (REAL FIX)
 * =========================== */

// SAME EXACT FORMAT AS PYTHON
function javaLikeTimestampGmt7() {
  const now = new Date();
  const local = new Date(now.getTime() + -7 * 60 * 60000);

  const yyyy = local.getUTCFullYear();
  const MM = String(local.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(local.getUTCDate()).padStart(2, "0");
  const hh = String(local.getUTCHours()).padStart(2, "0");
  const mm = String(local.getUTCMinutes()).padStart(2, "0");
  const ss = String(local.getUTCSeconds()).padStart(2, "0");

  const ms = String(Math.floor(local.getUTCMilliseconds() / 10)).padStart(2, "0");

  return `${yyyy}-${MM}-${dd}T${hh}:${mm}:${ss}.${ms}+07:00`;
}

// SAME AS PYTHON FOR SIGNATURE
function tsGmt7WithoutColon() {
  const now = new Date();
  const local = new Date(now.getTime() + -7 * 60 * 60000);

  const yyyy = local.getUTCFullYear();
  const MM = String(local.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(local.getUTCDate()).padStart(2, "0");
  const hh = String(local.getUTCHours()).padStart(2, "0");
  const mm = String(local.getUTCMinutes()).padStart(2, "0");
  const ss = String(local.getUTCSeconds()).padStart(2, "0");
  const ms = String(local.getUTCMilliseconds()).padStart(3, "0");

  return `${yyyy}-${MM}-${dd}T${hh}:${mm}:${ss}.${ms}+0700`;
}

/* ===========================
 * UTILS
 * =========================== */

function loadConfig(env) {
  return {
    API_KEY: env.API_KEY,
    BASE_API_URL: env.BASE_API_URL,
    BASE_CIAM_URL: env.BASE_CIAM_URL,
    UA: env.UA,
    BASIC_AUTH: env.BASIC_AUTH,
    AES_KEY_ASCII: env.AES_KEY_ASCII,
    ENCRYPTED_FIELD_KEY: env.ENCRYPTED_FIELD_KEY,
    AX_FP_KEY: env.AX_FP_KEY,
    XDATA_KEY: env.XDATA_KEY,
    AX_API_SIG_KEY: env.AX_API_SIG_KEY,
    X_API_BASE_SECRET: env.X_API_BASE_SECRET,
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
