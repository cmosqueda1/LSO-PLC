// api/_session.js
// IAM -> OMSv2 -> BI Dashboard (Redash) session helper
//
// Fix:
// - Do NOT store entire tough-cookie jar in browser cookie (too large)
// - Store ONLY small session payload: omsAccessToken + biCookies + authedAt
// - For follow-up calls, reconstruct a tough-cookie jar from biCookies and use fetch-cookie
//
// Required env vars:
//   SESSION_SECRET   (>= 16 chars)
//
// Vercel routes importing this MUST be node runtime:
//   export const config = { runtime: "nodejs" };

import crypto from "crypto";
import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IAM_BASE = "https://id.item.com";
const OMS_BASE = "https://omsv2.item.com";
const BI_BASE = "https://bi-dashboard.item.com";
const BI_HOST = "bi-dashboard.item.com";

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0";

const COOKIE_NAME = "plc_session";
const MAX_AGE_SECONDS = 60 * 60; // 1 hour
const REAUTH_TTL_MS = 15 * 60 * 1000; // 15 minutes

// --------------------
// Cookie crypto helpers
// --------------------
function assertSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error("Missing/weak SESSION_SECRET env var. Set SESSION_SECRET (>=16 chars) in Vercel env.");
  }
}

function getKey() {
  assertSecret();
  return crypto.createHash("sha256").update(process.env.SESSION_SECRET).digest(); // 32 bytes
}

function b64urlEncode(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlDecode(str) {
  str = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

function encryptJson(obj) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${b64urlEncode(iv)}.${b64urlEncode(tag)}.${b64urlEncode(ciphertext)}`;
}

function decryptJson(packed) {
  try {
    if (!packed) return null;
    const parts = String(packed).split(".");
    if (parts.length !== 3) return null;

    const [ivB, tagB, ctB] = parts;
    const iv = b64urlDecode(ivB);
    const tag = b64urlDecode(tagB);
    const ciphertext = b64urlDecode(ctB);

    const key = getKey();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) return;
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const {
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
    path = "/",
    maxAge = MAX_AGE_SECONDS,
  } = opts;

  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (path) parts.push(`Path=${path}`);
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  if (sameSite) parts.push(`SameSite=${sameSite}`);
  if (typeof maxAge === "number") parts.push(`Max-Age=${maxAge}`);

  const existing = res.getHeader("Set-Cookie");
  if (!existing) res.setHeader("Set-Cookie", parts.join("; "));
  else if (Array.isArray(existing)) res.setHeader("Set-Cookie", [...existing, parts.join("; ")]);
  else res.setHeader("Set-Cookie", [existing, parts.join("; ")]);
}

export function clearSession(res) {
  setCookie(res, COOKIE_NAME, "", { maxAge: 0 });
}

export function getSession(req) {
  const cookies = parseCookies(req);
  const packed = cookies[COOKIE_NAME];
  const data = decryptJson(packed);
  if (!data) return null;

  if (data.createdAt) {
    const ageMs = Date.now() - new Date(data.createdAt).getTime();
    if (ageMs > MAX_AGE_SECONDS * 1000) return null;
  }
  return data;
}

export function setSession(res, sessionData) {
  const payload = {
    ...sessionData,
    createdAt: new Date().toISOString(),
  };
  const packed = encryptJson(payload);
  setCookie(res, COOKIE_NAME, packed, { maxAge: MAX_AGE_SECONDS, secure: true });
}

// --------------------
// Flow helpers
// --------------------
function formEncode(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? "")}`)
    .join("&");
}

function getSetCookies(res) {
  if (typeof res.headers?.getSetCookie === "function") return res.headers.getSetCookie();
  const sc = res.headers?.get("set-cookie");
  return sc ? [sc] : [];
}

function jarGetCookieValue(jar, url, name) {
  return new Promise((resolve, reject) => {
    jar.getCookies(url, (err, cookies) => {
      if (err) return reject(err);
      const c = cookies.find((x) => x.key === name);
      resolve(c ? c.value : null);
    });
  });
}

function jarGetAllCookies(jar, url) {
  return new Promise((resolve, reject) => {
    jar.getCookies(url, (err, cookies) => {
      if (err) return reject(err);
      resolve(cookies || []);
    });
  });
}

function jarSetCookie(jar, cookieStr, url) {
  return new Promise((resolve, reject) => {
    jar.setCookie(cookieStr, url, { ignoreError: true }, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function loginIam(fetch, jar, username, password) {
  const body = formEncode({
    username,
    password,
    tenantId: "",
    verificationCode: "",
    extauth: "",
  });

  const r = await fetch(`${IAM_BASE}/login`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: IAM_BASE,
      Referer: `${IAM_BASE}/`,
      "x-channel": "WEB",
      "User-Agent": BROWSER_UA,
    },
    body,
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`IAM /login failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }

  const sess = await jarGetCookieValue(jar, IAM_BASE, "SESSION");
  if (!sess) throw new Error("IAM login did not yield SESSION cookie");
}

async function getIamAuthCode(fetch) {
  const authorizeUrl =
    `${IAM_BASE}/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=69d8d41b-651f-4af6-b3e9-04a33308034e` +
    `&scope=profile+email+phone+openid` +
    `&redirect_uri=${encodeURIComponent("https://omsv2.item.com/auth-code")}` +
    `&state=%252Fdashboard%252Fplc-report` +
    `&continue`;

  const r = await fetch(authorizeUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      Referer: `${IAM_BASE}/`,
      "User-Agent": BROWSER_UA,
    },
  });

  if (r.status !== 302) {
    const t = await r.text().catch(() => "");
    throw new Error(`Expected 302 from /oauth2/authorize, got ${r.status}: ${t.slice(0, 200)}`);
  }

  const loc = r.headers.get("location") || "";
  const u = new URL(loc);
  const code = u.searchParams.get("code");
  if (!code) throw new Error("No ?code= found in authorize redirect Location");

  const state = u.searchParams.get("state") || "%252Fdashboard%252Fplc-report";
  return { code, state };
}

async function visitOmsAuthCode(fetch, iamCode, state = "%252Fdashboard%252Fplc-report") {
  const url = `${OMS_BASE}/auth-code?code=${encodeURIComponent(iamCode)}&state=${encodeURIComponent(state)}`;

  const r = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      Origin: OMS_BASE,
      Referer: OMS_BASE,
      "User-Agent": BROWSER_UA,
    },
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`OMS /auth-code failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }
}

async function exchangeCodeForOmsToken(fetch, jar, iamCode) {
  const r = await fetch(`${OMS_BASE}/api/linker-oms/opc/iam/token`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/json",
      Origin: OMS_BASE,
      Referer: `${OMS_BASE}/auth-code`,
      "User-Agent": BROWSER_UA,
    },
    body: JSON.stringify({
      grantType: "authorization_code",
      iamCode,
      redirectUrl: "https://omsv2.item.com/auth-code",
    }),
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`OMS token exchange failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }

  const setCookies = getSetCookies(r);
  const accessCookie = setCookies.find((c) => c.startsWith("access_token="));
  if (accessCookie) {
    return accessCookie.split(";")[0].replace("access_token=", "").replace(/^"|"$/g, "");
  }

  const jarTok = await jarGetCookieValue(jar, OMS_BASE, "access_token");
  if (jarTok) return jarTok;

  const json = await r.json().catch(() => null);
  const possible =
    json?.access_token ||
    json?.accessToken ||
    json?.token ||
    json?.data?.access_token ||
    json?.data?.accessToken ||
    json?.data?.token;

  if (typeof possible === "string" && possible.length > 20) return possible;

  throw new Error("OMS access token not found in Set-Cookie, jar, or JSON.");
}

async function getBiIdToken(fetch, omsAccessToken) {
  const r = await fetch(`${OMS_BASE}/api/dms/app-api/bi/token`, {
    method: "GET",
    headers: {
      Accept: "application/json, text/plain, */*",
      Authorization: `Bearer ${omsAccessToken}`,
      Origin: OMS_BASE,
      Referer: `${OMS_BASE}/`,
      "User-Agent": BROWSER_UA,
    },
  });

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI token fetch failed HTTP ${r.status}`);

  const idToken = json?.id_token || json?.idToken || json?.data?.id_token || json?.data?.idToken;
  if (!idToken) throw new Error("BI token response missing id_token/idToken");
  return idToken;
}

async function verifyBiTokenAndSetCookies(fetch, jar, idToken) {
  const verifyUrl =
    `${BI_BASE}/oauth/verify_token?id_token=${encodeURIComponent(idToken)}` +
    `&next_path=${encodeURIComponent("/dashboards/2575")}`;

  const r = await fetch(verifyUrl, {
    method: "GET",
    redirect: "follow",
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      Origin: BI_BASE,
      Referer: BI_BASE,
      "User-Agent": BROWSER_UA,
    },
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`BI verify_token failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }

  const csrf = await jarGetCookieValue(jar, BI_BASE, "csrf_token");
  const sess = await jarGetCookieValue(jar, BI_BASE, "session");
  if (!csrf || !sess) throw new Error("BI verify_token completed but BI cookies (session/csrf_token) are missing");
}

// Build a real tough-cookie jar from stored BI cookies (keeps behavior like original working code)
async function buildJarFromStoredBiCookies(biCookies) {
  const jar = new tough.CookieJar();
  const entries = Object.entries(biCookies || {});
  for (const [k, v] of entries) {
    if (!k || v === undefined || v === null) continue;
    // Force Domain + Path to be broadly valid for API calls
    const cookieStr = `${k}=${v}; Domain=${BI_HOST}; Path=/; Secure`;
    await jarSetCookie(jar, cookieStr, BI_BASE);
  }
  return jar;
}

// --------------------
// Public API
// --------------------
export async function ensureAuthed(session, creds = null) {
  assertSecret();
  const now = Date.now();

  // Reuse existing session if fresh and has key cookies
  if (session?.authedAt && now - session.authedAt < REAUTH_TTL_MS && session?.omsAccessToken) {
    if (session?.biCookies?.csrf_token && session?.biCookies?.session) return session;
  }

  if (!creds?.username || !creds?.password) {
    throw new Error("Not authenticated. Please login.");
  }

  // Fresh login with a real jar (server-side)
  const jar = new tough.CookieJar();
  const fetch = fetchCookie(globalThis.fetch, jar);

  await loginIam(fetch, jar, creds.username, creds.password);

  const { code, state } = await getIamAuthCode(fetch);
  await visitOmsAuthCode(fetch, code, state);

  const omsToken = await exchangeCodeForOmsToken(fetch, jar, code);
  const idToken = await getBiIdToken(fetch, omsToken);
  await verifyBiTokenAndSetCookies(fetch, jar, idToken);

  // Store ONLY BI cookies (small)
  const biCookieList = await jarGetAllCookies(jar, BI_BASE);
  const biCookies = {};
  for (const c of biCookieList) biCookies[c.key] = c.value;

  if (!biCookies.csrf_token || !biCookies.session) {
    throw new Error(`BI cookies missing after auth. Found keys: ${Object.keys(biCookies).join(", ")}`);
  }

  return {
    authedAt: Date.now(),
    omsAccessToken: omsToken,
    biCookies,
  };
}

export async function callBiResults(session, payload) {
  assertSecret();

  // Reconstruct jar from stored cookies and let fetch-cookie format Cookie header correctly
  const jar = await buildJarFromStoredBiCookies(session?.biCookies);
  const fetch = fetchCookie(globalThis.fetch, jar);

  const csrf = session?.biCookies?.csrf_token;
  if (!csrf) throw new Error("Missing csrf_token in session. Login required.");

  const r = await fetch(`${BI_BASE}/api/queries/${payload.id}/results`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "x-csrf-token": csrf,
      Origin: BI_BASE,
      Referer: `${BI_BASE}/`,
      "User-Agent": BROWSER_UA,
    },
    body: JSON.stringify(payload),
  });

  const text = await r.text().catch(() => "");

  // Redash sometimes returns HTML (login/404). Surface that clearly.
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // If it's HTML, include a short snippet to help debugging
    throw new Error(`BI returned non-JSON. HTTP ${r.status}. Body: ${text.slice(0, 200)}…`);
  }

  if (!r.ok) {
    throw new Error(json?.message || json?.error || `BI results failed HTTP ${r.status}`);
  }

  return json;
}
