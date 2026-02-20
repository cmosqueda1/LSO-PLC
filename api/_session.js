import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IAM_BASE = "https://id.item.com";
const OMS_BASE = "https://omsv2.item.com";
const BI_BASE  = "https://bi-dashboard.item.com";

// Cache across warm invocations
let cached = globalThis.__biSession;
if (!cached) {
  cached = globalThis.__biSession = {
    jar: new tough.CookieJar(),
    authedAt: 0,
  };
}

const fetch = fetchCookie(globalThis.fetch, cached.jar);

function assertEnv() {
  const need = ["ITEM_USERNAME", "ITEM_PASSWORD"];
  const missing = need.filter(k => !process.env[k]);
  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }
}

function formEncode(obj) {
  return Object.entries(obj)
    .map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? "")}`)
    .join("&");
}

function getCookieValueForUrl(url, name) {
  // tough-cookie async API
  return new Promise((resolve, reject) => {
    cached.jar.getCookies(url, (err, cookies) => {
      if (err) return reject(err);
      const c = cookies.find(x => x.key === name);
      resolve(c ? c.value : null);
    });
  });
}

async function loginIam() {
  // POST /login (sets IAM SESSION cookie in jar)
  const body = formEncode({
    username: process.env.ITEM_USERNAME,
    password: process.env.ITEM_PASSWORD,
    tenantId: "",
    verificationCode: "",
    extauth: ""
  });

  const r = await fetch(`${IAM_BASE}/login`, {
    method: "POST",
    headers: {
      "Accept": "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "Origin": IAM_BASE,
      "Referer": `${IAM_BASE}/`,
      "x-channel": "WEB"
    },
    body,
    redirect: "manual"
  });

  if (!r.ok) {
    const t = await r.text();
    throw new Error(`IAM /login failed: HTTP ${r.status}: ${t.slice(0,200)}`);
  }
}

async function getIamAuthCode() {
  // Match HAR exactly (note the trailing "&continue" with no "=" value)
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
    const t = await r.text();
    throw new Error(`Expected 302 from /oauth2/authorize, got ${r.status}: ${t.slice(0,200)}`);
  }

  const loc = r.headers.get("location") || "";
  // Example from your HAR:
  // https://omsv2.item.com/auth-code?code=...&state=%252Fdashboard%252Fplc-report
  const u = new URL(loc);
  const code = u.searchParams.get("code");
  if (!code) throw new Error("No ?code= found in authorize redirect Location");

  return code;
}

async function exchangeCodeForOmsToken(iamCode) {
  const r = await fetch(`${OMS_BASE}/api/linker-oms/opc/iam/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grantType: "authorization_code",
      iamCode,
      redirectUrl: "https://omsv2.item.com/auth-code"
    })
  });

  if (!r.ok) {
    const t = await r.text();
    throw new Error(`OMS token exchange failed ${r.status}: ${t.slice(0,200)}`);
  }

  // 🔥 Extract access_token from Set-Cookie
  const raw = r.headers.raw?.()["set-cookie"] || [];
  const cookie = raw.find(c => c.startsWith("access_token="));

  if (!cookie) {
    throw new Error("OMS token cookie not found in Set-Cookie");
  }

  const token = cookie
    .split(";")[0]
    .replace("access_token=", "")
    .replace(/^"|"$/g, "");

  return token;
}

async function getBiIdToken(omsAccessToken) {
  const r = await fetch(`${OMS_BASE}/api/dms/app-api/bi/token`, {
    method: "GET",
    headers: { "Authorization": `Bearer ${omsAccessToken}` }
  });

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI token fetch failed HTTP ${r.status}`);
  const idToken = json?.id_token || json?.idToken;
  if (!idToken) throw new Error("BI token response missing id_token");
  return idToken;
}

async function verifyBiTokenAndSetCookies(idToken) {
  // This call is where Redash cookies get set in the jar (session + csrf_token)
  const verifyUrl =
    `${BI_BASE}/oauth/verify_token?id_token=${encodeURIComponent(idToken)}` +
    `&next_path=${encodeURIComponent("/dashboards/2575")}`;

  // follow redirects; jar will store Set-Cookie
  const r = await fetch(verifyUrl, { method: "GET", redirect: "follow" });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`BI verify_token failed HTTP ${r.status}: ${t.slice(0,200)}`);
  }
}

export async function ensureAuthed() {
  assertEnv();

  // Simple cache TTL (15 minutes) to avoid logging in every request on warm instance
  const now = Date.now();
  if (cached.authedAt && (now - cached.authedAt) < 15 * 60 * 1000) {
    // still ensure csrf exists
    const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
    const sess = await getCookieValueForUrl(BI_BASE, "session");
    if (csrf && sess) return;
  }

  // Full chain
  await loginIam();
  const code = await getIamAuthCode();
  const omsToken = await exchangeCodeForOmsToken(code);
  const idToken = await getBiIdToken(omsToken);
  await verifyBiTokenAndSetCookies(idToken);

  // Validate we have BI cookies
  const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
  const sess = await getCookieValueForUrl(BI_BASE, "session");
  if (!csrf || !sess) throw new Error("Auth chain completed but BI cookies (session/csrf_token) are missing");

  cached.authedAt = Date.now();
}

export async function callBiResults(payload) {
  await ensureAuthed();
  const csrf = await getCookieValueForUrl(BI_BASE, "csrf_token");
  if (!csrf) throw new Error("Missing csrf_token cookie");

  const r = await fetch(`${BI_BASE}/api/queries/${payload.id}/results`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrf
    },
    body: JSON.stringify(payload)
  });

  const json = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(json?.message || json?.error || `BI results failed HTTP ${r.status}`);
  return json;
}
