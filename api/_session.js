// api/_session.js
// IAM -> OMSv2 -> BI Dashboard (Redash) session helper
//
// Required env vars:
//   ITEM_USERNAME
//   ITEM_PASSWORD
//
// IMPORTANT: Your Vercel API routes that import this file MUST be node runtime:
//   export const config = { runtime: "nodejs" };

import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IAM_BASE = "https://id.item.com";
const OMS_BASE = "https://omsv2.item.com";
const BI_BASE = "https://bi-dashboard.item.com";

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0";

// cache across warm invocations
let cached = globalThis.__biSession;
if (!cached) {
  cached = globalThis.__biSession = {
    jar: new tough.CookieJar(),
    authedAt: 0,
    omsAccessToken: null,
  };
}

const fetch = fetchCookie(globalThis.fetch, cached.jar);

function assertEnv() {
  const need = ["ITEM_USERNAME", "ITEM_PASSWORD"];
  const missing = need.filter((k) => !process.env[k]);
  if (missing.length) throw new Error(`Missing env vars: ${missing.join(", ")}`);
}

function formEncode(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? "")}`)
    .join("&");
}

function getSetCookies(res) {
  // undici supports getSetCookie() in many environments
  if (typeof res.headers?.getSetCookie === "function") return res.headers.getSetCookie();
  // fallback single header
  const sc = res.headers?.get("set-cookie");
  return sc ? [sc] : [];
}

async function getCookieValueForUrl(url, name) {
  return new Promise((resolve, reject) => {
    cached.jar.getCookies(url, (err, cookies) => {
      if (err) return reject(err);
      const c = cookies.find((x) => x.key === name);
      resolve(c ? c.value : null);
    });
  });
}

async function loginIam() {
  const body = formEncode({
    username: process.env.ITEM_USERNAME,
    password: process.env.ITEM_PASSWORD,
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

  const sess = await getCookieValueForUrl(IAM_BASE, "SESSION");
  if (!sess) throw new Error("IAM login did not yield SESSION cookie");
}

async function getIamAuthCode() {
  // match HAR exactly
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

  // also return state in case you want to preserve it
  const state = u.searchParams.get("state") || "%252Fdashboard%252Fplc-report";
  return { code, state };
}

// 🔥 Missing hop in your server flow:
// Browser loads /auth-code first (HAR entry #2). That often establishes the OMS auth context
// and/or sets cookies that make /iam/token return the access_token cookie.
async function visitOmsAuthCode(iamCode, state = "%252Fdashboard%252Fplc-report") {
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

// OMS token exchange: token typically arrives as cookie "access_token" (your HAR evidence)
async function exchangeCodeForOmsToken(iamCode) {
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

  // Prefer Set-Cookie if exposed
  const setCookies = getSetCookies(r);
  const accessCookie = setCookies.find((c) => c.startsWith("access_token="));
  if (accessCookie) {
    return accessCookie.split(";")[0].replace("access_token=", "").replace(/^"|"$/g, "");
  }

  // Otherwise: rely on cookie jar storage (fetch-cookie should store it if present)
  const jarTok = await getCookieValueForUrl(OMS_BASE, "access_token");
  if (jarTok) return jarTok;

  // As a last resort: sometimes token comes in JSON (rare here, but safe)
  const json = await r.json().catch(() => null);
  const possible =
    json?.access_token ||
    json?.accessToken ||
    json?.token ||
    json?.data?.access_token ||
    json?.data?.accessToken ||
    json?.data?.token;
  if (typeof possible === "string" && possible.length > 20) return possible;

  throw new Error(`OMS token cookie not found and not present in jar/json. Set-Cookie names: ${JSON.stringify(setCookies.map(s => s.split("=")[0]))}`);
}

async function getBiIdToken(omsAccessToken) {
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
  if (!idToken) {
    throw new Error(`BI token response missing id_token/idToken. Keys: ${JSON.stringify(Object.keys(json || {}))}`);
  }
  return idToken;
}

async function verifyBiTokenAndSetCookies(idToken) {
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

  const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
  const sess = await getCookieValueForUrl(BI_BASE, "session");
  if (!csrf || !sess) throw new Error("BI verify_token completed but BI cookies (session/csrf_token) are missing");
}

export async function ensureAuthed() {
  assertEnv();

  const now = Date.now();
  const ttlMs = 15 * 60 * 1000;

  // quick warm-cache reuse
  if (cached.authedAt && now - cached.authedAt < ttlMs) {
    const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
    const sess = await getCookieValueForUrl(BI_BASE, "session");
    if (csrf && sess && cached.omsAccessToken) return;
  }

  await loginIam();

  const { code, state } = await getIamAuthCode();

  // 🔥 do the missing bootstrap hop
  await visitOmsAuthCode(code, state);

  // now token exchange
  const omsToken = await exchangeCodeForOmsToken(code);
  cached.omsAccessToken = omsToken;

  const idToken = await getBiIdToken(omsToken);
  await verifyBiTokenAndSetCookies(idToken);

  cached.authedAt = Date.now();
}

export async function callBiResults(payload) {
  await ensureAuthed();

  const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
  if (!csrf) throw new Error("Missing csrf_token cookie for BI results call");

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

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI results failed HTTP ${r.status}`);
  return json;
}
