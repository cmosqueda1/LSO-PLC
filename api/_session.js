// api/_session.js
// Full session/auth helper for IAM -> OMSv2 -> BI Dashboard (Redash) -> Query Results
// Requires Node runtime on Vercel API routes that import this file:
//   export const config = { runtime: "nodejs" };
//
// Env vars required:
//   ITEM_USERNAME
//   ITEM_PASSWORD
//
// Notes:
// - IAM login uses form-urlencoded and sets SESSION cookie for id.item.com
// - /oauth2/authorize returns 302 with ?code= (authorization code)
// - OMS token exchange sets OMS access_token as Set-Cookie on omsv2.item.com (per your HAR)
// - BI token endpoint returns id_token (or similar); then BI /oauth/verify_token sets BI session + csrf cookies
// - BI query results require x-csrf-token header (value from csrf_token cookie)

import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IAM_BASE = "https://id.item.com";
const OMS_BASE = "https://omsv2.item.com";
const BI_BASE  = "https://bi-dashboard.item.com";

// Cache across warm invocations (one jar per lambda instance)
let cached = globalThis.__biSession;
if (!cached) {
  cached = globalThis.__biSession = {
    jar: new tough.CookieJar(),
    authedAt: 0,
    omsAccessToken: null, // stored in-memory only
  };
}

// Wrap global fetch with cookie jar support for auto Set-Cookie handling
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

// Vercel/undici supports headers.getSetCookie(). Fallback to headers.get('set-cookie').
function getSetCookies(res) {
  if (typeof res.headers?.getSetCookie === "function") return res.headers.getSetCookie();
  const sc = res.headers?.get("set-cookie");
  return sc ? [sc] : [];
}

function cookieNameList(setCookies) {
  return (setCookies || []).map((c) => (c || "").split("=")[0]).filter(Boolean);
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
    headers: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: IAM_BASE,
      Referer: `${IAM_BASE}/`,
      "x-channel": "WEB",
    },
    body,
    redirect: "manual",
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`IAM /login failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }

  // Validate IAM SESSION cookie exists in jar (domain id.item.com)
  const sess = await getCookieValueForUrl(IAM_BASE, "SESSION");
  if (!sess) throw new Error("IAM login did not yield SESSION cookie");
}

async function getIamAuthCode() {
  // Match HAR exactly (including trailing &continue flag)
  const authorizeUrl =
    `${IAM_BASE}/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=69d8d41b-651f-4af6-b3e9-04a33308034e` +
    `&scope=profile+email+phone+openid` +
    `&redirect_uri=${encodeURIComponent("https://omsv2.item.com/auth-code")}` +
    `&state=%252Fdashboard%252Fplc-report` +
    `&continue`;

  const r = await fetch(authorizeUrl, { method: "GET", redirect: "manual" });

  if (r.status !== 302) {
    const t = await r.text().catch(() => "");
    throw new Error(`Expected 302 from /oauth2/authorize, got ${r.status}: ${t.slice(0, 200)}`);
  }

  const loc = r.headers.get("location") || "";
  const u = new URL(loc);
  const code = u.searchParams.get("code");
  if (!code) throw new Error("No ?code= found in authorize redirect Location");
  return code;
}

// OMS token exchange sets OMS access_token as Set-Cookie (per your HAR).
// We still allow the cookie jar to store it, but we ALSO capture the raw token value
// to use as Authorization: Bearer <token> on subsequent OMS API calls.
async function exchangeCodeForOmsToken(iamCode) {
  const r = await fetch(`${OMS_BASE}/api/linker-oms/opc/iam/token`, {
    method: "POST",
    // We don't follow redirects automatically here so we can capture cookies per-hop if needed
    redirect: "manual",
    headers: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/json",
      Origin: OMS_BASE,
      Referer: `${OMS_BASE}/auth-code`,
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

  // Some implementations may set it on a redirect hop. If we got redirected, follow the hop.
  if (!accessCookie && (r.status === 302 || r.status === 303)) {
    const loc = r.headers.get("location");
    if (!loc) throw new Error(`OMS token exchange redirect ${r.status} missing Location`);
    // Follow the redirect using the cookie jar-managed fetch (cookies persist in jar)
    const r2 = await fetch(loc, { method: "GET", redirect: "manual" });
    const sc2 = getSetCookies(r2);
    const ac2 = sc2.find((c) => c.startsWith("access_token="));
    if (ac2) {
      const token = ac2.split(";")[0].replace("access_token=", "").replace(/^"|"$/g, "");
      return token;
    }
  }

  if (!accessCookie) {
    // Last chance: the cookie jar might have it even if Set-Cookie isn't exposed
    // (rare, but keep it)
    const jarTok = await getCookieValueForUrl(OMS_BASE, "access_token");
    if (jarTok) return jarTok;

    throw new Error(
      `OMS token cookie not found. Set-Cookie names: ${JSON.stringify(cookieNameList(setCookies))}`
    );
  }

  const token = accessCookie.split(";")[0].replace("access_token=", "").replace(/^"|"$/g, "");
  return token;
}

// BI token endpoint typically requires OMS bearer auth.
// Your earlier flow: GET /api/dms/app-api/bi/token using Authorization: Bearer <omsAccessToken>
async function getBiIdToken(omsAccessToken) {
  const r = await fetch(`${OMS_BASE}/api/dms/app-api/bi/token`, {
    method: "GET",
    headers: {
      Accept: "application/json, text/plain, */*",
      Authorization: `Bearer ${omsAccessToken}`,
      Origin: OMS_BASE,
      Referer: `${OMS_BASE}/`,
    },
  });

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI token fetch failed HTTP ${r.status}`);

  // Try common field names. We can expand if your response differs.
  const idToken = json?.id_token || json?.idToken || json?.data?.id_token || json?.data?.idToken;
  if (!idToken) {
    const keys = Object.keys(json || {});
    throw new Error(`BI token response missing id_token/idToken. Top-level keys: ${JSON.stringify(keys)}`);
  }
  return idToken;
}

// This call sets BI cookies (session, csrf_token, remember_token, etc.) on bi-dashboard.item.com
async function verifyBiTokenAndSetCookies(idToken) {
  const verifyUrl =
    `${BI_BASE}/oauth/verify_token?id_token=${encodeURIComponent(idToken)}` +
    `&next_path=${encodeURIComponent("/dashboards/2575")}`;

  const r = await fetch(verifyUrl, { method: "GET", redirect: "follow" });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`BI verify_token failed HTTP ${r.status}: ${t.slice(0, 200)}`);
  }

  // Validate BI cookies exist
  const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
  const sess = await getCookieValueForUrl(BI_BASE, "session");
  if (!csrf || !sess) {
    throw new Error("BI verify_token completed but BI cookies (session/csrf_token) are missing");
  }
}

export async function ensureAuthed() {
  assertEnv();

  const now = Date.now();
  const ttlMs = 15 * 60 * 1000; // 15 minutes cache per warm instance

  // If cached and cookies still present, skip full auth
  if (cached.authedAt && now - cached.authedAt < ttlMs) {
    const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
    const sess = await getCookieValueForUrl(BI_BASE, "session");
    if (csrf && sess && cached.omsAccessToken) return;
  }

  // Full chain
  await loginIam();
  const code = await getIamAuthCode();
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
    },
    body: JSON.stringify(payload),
  });

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI results failed HTTP ${r.status}`);
  return json;
}
