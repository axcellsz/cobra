// src/worker.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --- API ROUTES ---
    if (url.pathname === "/api/get-otp" && request.method === "POST") {
      return handleGetOtp(request, env);
    }

    if (url.pathname === "/api/submit-otp" && request.method === "POST") {
      return handleSubmitOtp(request, env);
    }

    // Contoh API: load profile (setara get_profile di engsel.py)
    if (url.pathname === "/api/profile" && request.method === "POST") {
      return handleProfile(request, env);
    }

    // --- STATIC FILES FROM KV (Pages2) ---
    return handleStatic(url, env);
  },
};

/* ===========================
 * STATIC FILE HANDLER (KV)
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
 *  API: GET OTP
 *  (mirip get_otp di ciam.py)
 * =========================== */

async function handleGetOtp(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.msisdn) {
    return json({ ok: false, message: "msisdn is required" }, 400);
  }

  const msisdn = String(body.msisdn);
  if (!msisdn.startsWith("628") || msisdn.length > 14) {
    return json({ ok: false, message: "Invalid msisdn" }, 400);
  }

  const config = loadConfig(env);
  const axFp = await loadAxFp(env, config);
  const axDeviceId = await computeAxDeviceId(axFp);

  const url = config.BASE_CIAM_URL + "/realms/xl-ciam/auth/otp";

  const now = new Date();
  const axRequestAt = javaLikeTimestampGmt7(now);
  const axRequestId = crypto.randomUUID();

  const params = new URLSearchParams({
    contact: msisdn,
    contactType: "SMS",
    alternateContact: "false",
  });

  const headers = {
    "Accept-Encoding": "gzip, deflate, br",
    "Authorization": `Basic ${config.BASIC_AUTH}`,
    "Ax-Device-Id": axDeviceId,
    "Ax-Fingerprint": axFp,
    "Ax-Request-At": axRequestAt,
    "Ax-Request-Device": "samsung",
    "Ax-Request-Device-Model": "SM-N935F",
    "Ax-Request-Id": axRequestId,
    "Ax-Substype": "PREPAID",
    "Content-Type": "application/json",
    "Host": config.BASE_CIAM_URL.replace("https://", ""),
    "User-Agent": config.UA,
  };

  const resp = await fetch(url + "?" + params.toString(), {
    method: "GET",
    headers,
  });

  const text = await resp.text();
  let jsonBody;
  try {
    jsonBody = JSON.parse(text);
  } catch (_) {
    return json(
      { ok: false, message: "Invalid JSON from CIAM", raw: text },
      502
    );
  }

  if (!jsonBody.subscriber_id) {
    return json(
      {
        ok: false,
        message: jsonBody.error || "Subscriber ID not found",
        raw: jsonBody,
      },
      400
    );
  }

  const subscriberId = jsonBody.subscriber_id;

  // Simpan subscriber_id per msisdn
  await env.Pages2.put(`SUB_ID:${msisdn}`, subscriberId);

  return json({ ok: true, subscriber_id: subscriberId });
}

/* ===========================
 *  API: SUBMIT OTP (LOGIN)
 *  (mirip submit_otp di ciam.py)
 * =========================== */

async function handleSubmitOtp(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.msisdn || !body.otp) {
    return json({ ok: false, message: "msisdn & otp required" }, 400);
  }

  const msisdn = String(body.msisdn);
  const otp = String(body.otp);

  if (!msisdn.startsWith("628") || msisdn.length > 14) {
    return json({ ok: false, message: "Invalid msisdn" }, 400);
  }
  if (otp.length !== 6) {
    return json({ ok: false, message: "OTP must be 6 digits" }, 400);
  }

  const config = loadConfig(env);
  const axFp = await loadAxFp(env, config);
  const axDeviceId = await computeAxDeviceId(axFp);

  const url =
    config.BASE_CIAM_URL + "/realms/xl-ciam/protocol/openid-connect/token";

  const now = new Date();
  const tsForSign = tsGmt7WithoutColon(now);
  const tsHeader = tsGmt7WithoutColon(
    new Date(now.getTime() - 5 * 60 * 1000)
  );

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
    "Authorization": `Basic ${config.BASIC_AUTH}`,
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
  let jsonBody;
  try {
    jsonBody = JSON.parse(text);
  } catch (_) {
    return json(
      { ok: false, message: "Invalid JSON from CIAM", raw: text },
      502
    );
  }

  if (jsonBody.error) {
    return json(
      {
        ok: false,
        message: jsonBody.error_description || jsonBody.error,
        raw: jsonBody,
      },
      400
    );
  }

  const tokens = {
    access_token: jsonBody.access_token,
    id_token: jsonBody.id_token,
    refresh_token: jsonBody.refresh_token,
    expires_in: jsonBody.expires_in,
    token_type: jsonBody.token_type,
  };

  // Simpan refresh_token ke KV (A: central store), mirip AuthInstance.refresh_tokens
  await addRefreshToken(env, msisdn, tokens);

  return json({ ok: true, tokens });
}

/* ===========================
 *  CONTOH API: PROFILE
 *  setara get_profile() di engsel.py
 * =========================== */

async function handleProfile(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.msisdn || !body.tokens) {
    return json(
      { ok: false, message: "msisdn & tokens (access_token, id_token) required" },
      400
    );
  }

  const msisdn = String(body.msisdn);
  const tokens = body.tokens;
  const accessToken = tokens.access_token;
  const idToken = tokens.id_token;

  if (!accessToken || !idToken) {
    return json(
      { ok: false, message: "access_token & id_token wajib dikirim" },
      400
    );
  }

  const config = loadConfig(env);

  // Muat record refresh_token dari KV (kalau suatu saat mau refresh otomatis)
  const record = await findRefreshRecord(env, msisdn);
  if (!record) {
    // tetap lanjut pakai token dari browser, tapi kasih warning di response
  }

  // Sama seperti get_profile di engsel.py:
  // path = "api/v8/profile"
  // raw_payload = {
  //   "access_token": access_token,
  //   "app_version": "8.9.0",
  //   "is_enterprise": False,
  //   "lang": "en"
  // }
  const path = "api/v8/profile";
  const payload = {
    access_token: accessToken,
    app_version: "8.9.0",
    is_enterprise: false,
    lang: "en",
  };

  const res = await callMyxlXApi(env, config, {
    method: "POST",
    path,
    idToken,
    payload,
  });

  return res;
}

/* ===========================
 *  REFRESH TOKEN STORAGE (KV)
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

async function findRefreshRecord(env, msisdn) {
  const number = Number(msisdn);
  const list = await loadRefreshTokens(env);
  return list.find((x) => x.number === number) || null;
}

async function addRefreshToken(env, msisdn, tokens) {
  const number = Number(msisdn);
  const list = await loadRefreshTokens(env);

  const subscriberId = (await env.Pages2.get(`SUB_ID:${msisdn}`)) || "";

  let existing = list.find((x) => x.number === number);

  if (existing) {
    existing.refresh_token = tokens.refresh_token;
    existing.subscriber_id = subscriberId || existing.subscriber_id || "";
  } else {
    list.push({
      number,
      subscriber_id: subscriberId,
      subscription_type: "",
      refresh_token: tokens.refresh_token,
    });
  }

  await saveRefreshTokens(env, list);
  await env.Pages2.put("ACTIVE_NUMBER", String(number));
}

/* ===========================
 *  FINGERPRINT & DEVICE ID
 * =========================== */

async function loadAxFp(env, config) {
  const existing = await env.Pages2.get("AX_FP");
  if (existing) return existing;

  // Generate 1x, lalu simpan permanen, seperti ax.fp di Termux
  const rand = () => Math.floor(Math.random() * 9000 + 1000);
  const manufacturer = `samsung${rand()}`;
  const model = `SM-N93${rand()}`;
  const lang = "en";
  const resolution = "720x1540";
  const tzShort = "GMT07:00";
  const ip = "192.169.69.69";
  const fontScale = 1.0;
  const androidRelease = "13";
  const msisdn = "6281398370564";

  const plain =
    `${manufacturer}|${model}|${lang}|${resolution}|` +
    `${tzShort}|${ip}|${fontScale}|Android ${androidRelease}|${msisdn}`;

  // AX_FP_KEY sebagai ASCII (16-byte) sesuai encrypt.py
  const keyBytes = new TextEncoder().encode(config.AX_FP_KEY);
  const iv = new Uint8Array(16); // 0x00 * 16

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );

  const ptBytes = new TextEncoder().encode(plain);
  const blockSize = 16;
  const padLen = blockSize - (ptBytes.length % blockSize || blockSize);
  const padded = new Uint8Array(ptBytes.length + padLen);
  padded.set(ptBytes);
  padded.fill(padLen, ptBytes.length);

  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    padded
  );

  let bin = "";
  for (const b of new Uint8Array(ct)) bin += String.fromCharCode(b);
  const b64 = btoa(bin);

  await env.Pages2.put("AX_FP", b64);
  return b64;
}

async function computeAxDeviceId(axFp) {
  // Di Python: md5(android_id) -> 32 hex; di sini pakai sha256 lalu ambil 32 char
  const hashHex = await sha256hex(axFp);
  return hashHex.slice(0, 32);
}

/* ===========================
 *  AX API SIGNATURE (OTP)
 *  (make_ax_api_signature di encrypt.py)
 * =========================== */

async function makeAxApiSignature(config, ts, contact, code, contactType) {
  const preimage = `${ts}password${contactType}${contact}${code}openid`;

  const keyBytes = new TextEncoder().encode(config.AX_API_SIG_KEY);
  const msgBytes = new TextEncoder().encode(preimage);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  const sigBytes = new Uint8Array(sig);

  let bin = "";
  for (const b of sigBytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/* ===========================
 *  XDATA & X_SIGNATURE
 *  (encrypt_xdata & make_x_signature)
 * =========================== */

async function deriveIv(xtimeMs) {
  const txt = String(xtimeMs);
  const data = new TextEncoder().encode(txt);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const hex = [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const ivAscii = hex.slice(0, 16); // 16 char hex jadi 16 byte ASCII
  return new TextEncoder().encode(ivAscii);
}

function pkcs7Pad(bytes, blockSize) {
  const padLen = blockSize - (bytes.length % blockSize || blockSize);
  const out = new Uint8Array(bytes.length + padLen);
  out.set(bytes);
  out.fill(padLen, bytes.length);
  return out;
}

function pkcs7Unpad(bytes) {
  if (bytes.length === 0) return bytes;
  const padLen = bytes[bytes.length - 1];
  return bytes.slice(0, bytes.length - padLen);
}

async function encryptXData(config, plaintext) {
  const xtime = Date.now();
  const iv = await deriveIv(xtime);
  const keyBytes = new TextEncoder().encode(config.XDATA_KEY);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );

  const ptBytes = new TextEncoder().encode(plaintext);
  const padded = pkcs7Pad(ptBytes, 16);

  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    padded
  );

  let bin = "";
  for (const b of new Uint8Array(ct)) bin += String.fromCharCode(b);
  let b64 = btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return { xdata: b64, xtime };
}

async function decryptXData(config, xdata, xtime) {
  const iv = await deriveIv(xtime);
  const keyBytes = new TextEncoder().encode(config.XDATA_KEY);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  let s = xdata.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  const ctBytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  const pt = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    key,
    ctBytes
  );

  const unpadded = pkcs7Unpad(new Uint8Array(pt));
  return new TextDecoder().decode(unpadded);
}

async function makeXSignature(config, idToken, method, path, sigTimeSec) {
  const keyStr = `${config.X_API_BASE_SECRET};${idToken};${method};${path};${sigTimeSec}`;
  const keyBytes = new TextEncoder().encode(keyStr);

  const msg = `${idToken};${sigTimeSec};`;
  const msgBytes = new TextEncoder().encode(msg);

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/* ===========================
 *  GENERIC CALL MYXL (ENGSEL)
 *  setara send_api_request di engsel.py
 * =========================== */

async function callMyxlXApi(env, config, opts) {
  const { method, path, idToken, payload } = opts;

  const plainBody = JSON.stringify(payload || {});
  const { xdata, xtime } = await encryptXData(config, plainBody);
  const sigTimeSec = Math.floor(xtime / 1000);

  const xSig = await makeXSignature(
    config,
    idToken,
    method.toUpperCase(),
    path,
    sigTimeSec
  );

  const now = new Date();
  const xRequestAt = javaLikeTimestampGmt7(now);

  const headers = {
    host: config.BASE_API_URL.replace("https://", ""),
    "content-type": "application/json; charset=utf-8",
    "user-agent": config.UA,
    "x-api-key": config.API_KEY,
    authorization: `Bearer ${idToken}`,
    "x-hv": "v3",
    "x-signature-time": String(sigTimeSec),
    "x-signature": xSig,
    "x-request-id": crypto.randomUUID(),
    "x-request-at": xRequestAt,
    "x-version-app": "8.9.0",
  };

  const url = `${config.BASE_API_URL}/${path}`;
  const body = JSON.stringify({ xdata, xtime });

  const resp = await fetch(url, {
    method,
    headers,
    body,
  });

  const text = await resp.text();
  let jsonResp;
  try {
    jsonResp = JSON.parse(text);
  } catch {
    return json(
      {
        ok: resp.ok,
        status: resp.status,
        raw: text,
      },
      resp.ok ? 200 : resp.status
    );
  }

  // Coba decrypt kalau bentuknya {xdata, xtime}
  let decrypted = null;
  try {
    if (
      jsonResp &&
      typeof jsonResp === "object" &&
      "xdata" in jsonResp &&
      "xtime" in jsonResp
    ) {
      const plain = await decryptXData(config, jsonResp.xdata, jsonResp.xtime);
      decrypted = JSON.parse(plain);
    }
  } catch (e) {
    // kalau gagal decrypt, skip saja
  }

  return json(
    {
      ok: resp.ok,
      status: resp.status,
      raw: jsonResp,
      data: decrypted,
    },
    resp.ok ? 200 : resp.status
  );
}

/* ===========================
 *  TIMESTAMP UTILS (GMT+7)
 * =========================== */

function toGmt7(date) {
  const utcMs = date.getTime() + date.getTimezoneOffset() * 60000;
  return new Date(utcMs + 7 * 60 * 60000);
}

// untuk header OTP & X-Request-At
function javaLikeTimestampGmt7(now) {
  const d = toGmt7(now);
  const ms2 = String(Math.floor(d.getMilliseconds() / 10)).padStart(2, "0");
  const yyyy = d.getUTCFullYear();
  const MM = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  return `${yyyy}-${MM}-${dd}T${hh}:${mm}:${ss}.${ms2}+07:00`;
}

// untuk AX-Api-Signature & headers CIAM
function tsGmt7WithoutColon(now) {
  const d = toGmt7(now);
  const millis = String(d.getMilliseconds()).padStart(3, "0");
  const yyyy = d.getUTCFullYear();
  const MM = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  return `${yyyy}-${MM}-${dd}T${hh}:${mm}:${ss}.${millis}+0700`;
}

/* ===========================
 *  CONFIG & UTILS
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
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
