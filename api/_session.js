// api/_session.js
import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IAM_BASE = "https://id.item.com";
const OMS_BASE = "https://omsv2.item.com";
const BI_BASE = "https://bi-dashboard.item.com";

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

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

function getCookieValueForUrl(jar, url, name) {
  return new Promise((resolve, reject) => {
    jar.getCookies(url, (err, cookies) => {
      if (err) return reject(err);
      const c = cookies.find((x) => x.key === name);
      resolve(c ? c.value : null);
    });
  });
}

function serializeJar(jar) {
  return new Promise((resolve, reject) => {
    jar.serialize((err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
}

function deserializeJar(jarJson) {
  if (!jarJson) return new tough.CookieJar();
  return new Promise((resolve, reject) => {
    tough.CookieJar.deserialize(jarJson, (err, jar) => {
      if (err) return reject(err);
      resolve(jar);
    });
  });
}

async function loginIam(fetch, jar, username, password) {
  const r = await fetch(`${IAM_BASE}/login`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: IAM_BASE,
      Referer: `${IAM_BASE}/`,
      "User-Agent": BROWSER_UA,
      "x-channel": "WEB"
    },
    body: formEncode({
      username,
      password,
      tenantId: "",
      verificationCode: "",
      extauth: ""
    })
  });

  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`IAM login failed: ${r.status} ${t.slice(0,200)}`);
  }

  const sess = await getCookieValueForUrl(jar, IAM_BASE, "SESSION");
  if (!sess) throw new Error("IAM SESSION cookie missing after login");
}

async function getIamAuthCode(fetch) {
  const authorizeUrl =
    `${IAM_BASE}/oauth2/authorize?response_type=code` +
    `&client_id=69d8d41b-651f-4af6-b3e9-04a33308034e` +
    `&scope=profile+email+phone+openid` +
    `&redirect_uri=${encodeURIComponent("https://omsv2.item.com/auth-code")}` +
    `&state=%252Fdashboard%252Fplc-report&continue`;

  const r = await fetch(authorizeUrl, { method: "GET", redirect: "manual" });

  if (r.status !== 302) throw new Error("Failed to obtain IAM auth code");

  const loc = r.headers.get("location");
  const u = new URL(loc);
  return {
    code: u.searchParams.get("code"),
    state: u.searchParams.get("state")
  };
}

async function visitOmsAuthCode(fetch, code, state) {
  await fetch(
    `${OMS_BASE}/auth-code?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    { method: "GET", redirect: "follow" }
  );
}

async function exchangeCodeForOmsToken(fetch, jar, code) {
  const r = await fetch(`${OMS_BASE}/api/linker-oms/opc/iam/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: OMS_BASE,
      Referer: `${OMS_BASE}/auth-code`
    },
    body: JSON.stringify({
      grantType: "authorization_code",
      iamCode: code,
      redirectUrl: "https://omsv2.item.com/auth-code"
    })
  });

  if (!r.ok) throw new Error("OMS token exchange failed");

  const cookies = getSetCookies(r);
  const tokenCookie = cookies.find((c) => c.startsWith("access_token="));
  if (tokenCookie) {
    return tokenCookie.split(";")[0].replace("access_token=", "").replace(/^"|"$/g, "");
  }

  const jarTok = await getCookieValueForUrl(jar, OMS_BASE, "access_token");
  if (jarTok) return jarTok;

  throw new Error("OMS access_token not found");
}

async function getBiToken(fetch, omsToken) {
  const r = await fetch(`${OMS_BASE}/api/dms/app-api/bi/token`, {
    headers: { Authorization: `Bearer ${omsToken}` }
  });

  const json = await r.json();
  if (!r.ok) throw new Error("BI token fetch failed");

  return json?.id_token || json?.data?.id_token;
}

async function verifyBi(fetch, idToken) {
  await fetch(
    `${BI_BASE}/oauth/verify_token?id_token=${encodeURIComponent(idToken)}&next_path=%2Fdashboards%2F2575`,
    { method: "GET", redirect: "follow" }
  );
}

export async function ensureAuthed(session, creds = null) {
  const jar = await deserializeJar(session?.jarJson);
  const fetch = fetchCookie(globalThis.fetch, jar);

  // reuse session
  if (!creds && session?.authedAt && Date.now() - session.authedAt < 15 * 60 * 1000) {
    return session;
  }

  if (!creds?.username || !creds?.password)
    throw new Error("Not authenticated. Please login.");

  await loginIam(fetch, jar, creds.username, creds.password);

  const { code, state } = await getIamAuthCode(fetch);
  await visitOmsAuthCode(fetch, code, state);

  const omsToken = await exchangeCodeForOmsToken(fetch, jar, code);
  const idToken = await getBiToken(fetch, omsToken);
  await verifyBi(fetch, idToken);

  return {
    jarJson: await serializeJar(jar),
    authedAt: Date.now(),
    omsAccessToken: omsToken
  };
}

export async function callBiResults(session, payload) {
  const jar = await deserializeJar(session.jarJson);
  const fetch = fetchCookie(globalThis.fetch, jar);

  const csrf = await getCookieValueForUrl(jar, BI_BASE, "csrf_token");

  const r = await fetch(`${BI_BASE}/api/queries/${payload.id}/results`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrf
    },
    body: JSON.stringify(payload)
  });

  if (!r.ok) throw new Error("BI results fetch failed");
  return r.json();
}
