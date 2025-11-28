// ==========================
// WORKER.JS FINAL (MODE A)
// ==========================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ----------------------------
    //            AUTH
    // ----------------------------
    if (url.pathname === "/api/get-otp" && request.method === "POST")
      return handleGetOtp(request, env);

    if (url.pathname === "/api/submit-otp" && request.method === "POST")
      return handleSubmitOtp(request, env);

    if (url.pathname === "/api/profile" && request.method === "POST")
      return handleProfile(request, env);

    // ----------------------------
    //         PACKAGE API
    // ----------------------------
    if (url.pathname === "/api/packs" && request.method === "POST")
      return handleListPackages(request, env);

    if (url.pathname === "/api/buy" && request.method === "POST")
      return handleBuyPackage(request, env);

    // ----------------------------
    //     STATIC FILES (KV)
    // ----------------------------
    return handleStatic(url, env);
  }
};

// ===============================
// STATIC HTML FROM KV
// ===============================
async function handleStatic(url, env) {
  let key = url.pathname.replace(/^\/+/, "");
  if (!key) key = "index.html";

  const body = await env.Pages2.get(key, { type: "stream" });
  if (!body) return new Response("Not found", { status: 404 });

  return new Response(body, {
    headers: { "content-type": mime(key) }
  });
}

function mime(path) {
  if (path.endsWith(".html")) return "text/html";
  if (path.endsWith(".js")) return "text/javascript";
  if (path.endsWith(".css")) return "text/css";
  return "text/plain";
}

// ===============================
// 1) SEND OTP
// ===============================
async function handleGetOtp(request, env) {
  const { msisdn } = await request.json().catch(() => ({}));
  if (!msisdn || !msisdn.startsWith("628"))
    return json({ ok: false, message: "Invalid number" }, 400);

  const cfg = loadConfig(env);
  const axFp = await loadAxFp(env, cfg);
  const axDev = await computeAxDeviceId(axFp);

  const url =
    cfg.BASE_CIAM_URL + "/realms/xl-ciam/auth/otp?" +
    new URLSearchParams({
      contact: msisdn,
      contactType: "SMS",
      alternateContact: "false"
    });

  const headers = {
    "Authorization": `Basic ${cfg.BASIC_AUTH}`,
    "Ax-Device-Id": axDev,
    "Ax-Fingerprint": axFp,
    "Ax-Request-At": javaTS(),
    "Ax-Request-Id": crypto.randomUUID(),
    "Ax-Request-Device": "samsung",
    "Ax-Request-Device-Model": "SM-N935F",
    "Ax-Substype": "PREPAID",
    "User-Agent": cfg.UA
  };

  const r = await fetch(url, { headers });
  const t = await r.text();

  let j;
  try { j = JSON.parse(t); } catch { return json({ ok: false, raw: t }, 500); }

  if (!j.subscriber_id)
    return json({ ok: false, message: "Failed", raw: j }, 400);

  await env.Pages2.put(`SUB:${msisdn}`, j.subscriber_id);

  return json({ ok: true, subscriber_id: j.subscriber_id });
}

// ===============================
// 2) SUBMIT OTP
// ===============================
async function handleSubmitOtp(request, env) {
  const { msisdn, otp } = await request.json().catch(() => ({}));
  if (!msisdn || !otp) return json({ ok: false }, 400);

  const cfg = loadConfig(env);
  const axFp = await loadAxFp(env, cfg);
  const axDev = await computeAxDeviceId(axFp);

  const ts = tsNoColon();
  const tsHead = tsNoColonMinus5();

  const signature = await hmacAx(
    cfg.AX_API_SIG_KEY,
    `${ts}passwordSMS${msisdn}${otp}openid`
  );

  const payload = new URLSearchParams({
    contactType: "SMS",
    code: otp,
    grant_type: "password",
    contact: msisdn,
    scope: "openid"
  });

  const headers = {
    "Authorization": `Basic ${cfg.BASIC_AUTH}`,
    "Ax-Api-Signature": signature,
    "Ax-Device-Id": axDev,
    "Ax-Fingerprint": axFp,
    "Ax-Request-At": tsHead,
    "Ax-Request-Id": crypto.randomUUID(),
    "Ax-Request-Device": "samsung",
    "Ax-Request-Device-Model": "SM-N935F",
    "User-Agent": cfg.UA,
    "Content-Type": "application/x-www-form-urlencoded"
  };

  const r = await fetch(
    cfg.BASE_CIAM_URL + "/realms/xl-ciam/protocol/openid-connect/token",
    { method: "POST", headers, body: payload.toString() }
  );

  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { return json({ ok: false, raw: t }, 500); }

  if (j.error) return json({ ok: false, raw: j }, 400);

  return json({ ok: true, tokens: j });
}

// ===============================
// 3) PROFILE (AUTO LOAD)
// ===============================
async function handleProfile(request, env) {
  const { access_token } = await request.json().catch(() => ({}));
  if (!access_token) return json({ ok: false }, 400);

  const cfg = loadConfig(env);

  const r = await fetch(
    cfg.BASE_CIAM_URL + "/realms/xl-ciam/protocol/openid-connect/userinfo",
    {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "User-Agent": cfg.UA
      }
    }
  );

  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { return json({ ok: false, raw: t }, 500); }

  if (j.error) return json({ ok: false, raw: j }, 400);

  return json({ ok: true, profile: j });
}

// ===============================
// 4) LIST PACKAGE (SIMPLE VERSION)
// ===============================
async function handleListPackages(request, env) {
  const { access_token } = await request.json().catch(() => ({}));
  if (!access_token) return json({ ok: false }, 400);

  const cfg = loadConfig(env);

  const url = cfg.BASE_API_URL + "/api/v1/package/categories";

  const r = await fetch(url, {
    headers: {
      Authorization: `Bearer ${access_token}`,
      "User-Agent": cfg.UA
    }
  });

  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { return json({ ok: false, raw: t }, 500); }

  return json({ ok: true, data: j });
}

// ===============================
// 5) BUY PACKAGE (VERY SIMPLE)
// ===============================
async function handleBuyPackage(request, env) {
  const { access_token, package_id } = await request.json().catch(() => ({}));
  if (!access_token || !package_id)
    return json({ ok: false, message: "Missing" }, 400);

  const cfg = loadConfig(env);

  const url = cfg.BASE_API_URL + "/api/v1/package/buy";

  const r = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "User-Agent": cfg.UA,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ package_id })
  });

  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { return json({ ok: false, raw: t }, 500); }

  return json({ ok: true, result: j });
}

// =====================================
// UTIL
// =====================================
function loadConfig(env) {
  return {
    BASE_API_URL: env.BASE_API_URL,
    BASE_CIAM_URL: env.BASE_CIAM_URL,
    BASIC_AUTH: env.BASIC_AUTH,
    UA: env.UA,
    AX_FP_KEY: env.AX_FP_KEY,
    AX_API_SIG_KEY: env.AX_API_SIG_KEY
  };
}

function javaTS() {
  const d = new Date();
  return d.toISOString().replace("Z", "+07:00");
}

function tsNoColon() {
  const d = new Date();
  return d.toISOString().replace(/[:-]/g, "").replace("Z", "+0700");
}

function tsNoColonMinus5() {
  const d = new Date(Date.now() - 5 * 60 * 1000);
  return d.toISOString().replace(/[:-]/g, "").replace("Z", "+0700");
}

// ---------------- FINGERPRINT ----------------
async function loadAxFp(env, cfg) {
  const old = await env.Pages2.get("AXFP");
  if (old) return old;

  const plain = `samsung|SM-N935F|en|720x1540|GMT07:00|192.169.69.69|1.0|Android 13|6281398370564`;
  const key = new TextEncoder().encode(cfg.AX_FP_KEY).slice(0, 32);
  const iv = new Uint8Array(16);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, "AES-CBC", false, ["encrypt"]
  );

  const buf = new TextEncoder().encode(plain);
  const pad = 16 - (buf.length % 16);
  const padded = new Uint8Array([...buf, ...new Array(pad).fill(pad)]);

  const enc = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, padded);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(enc)));

  await env.Pages2.put("AXFP", b64);
  return b64;
}

async function computeAxDeviceId(axFp) {
  const arr = new TextEncoder().encode(axFp);
  const hash = await crypto.subtle.digest("SHA-256", arr);
  return [...new Uint8Array(hash)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

// ---------------- HMAC SIGNATURE ----------------
async function hmacAx(keyAscii, text) {
  const key = new TextEncoder().encode(keyAscii);
  const msg = new TextEncoder().encode(text);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msg);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function json(o, s = 200) {
  return new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json" }
  });
}
