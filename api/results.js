export const config = { runtime: "nodejs" };

import { ensureAuthed, callBiResults, getSession, setSession } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  try {
    const payload = req.body;
    if (!payload?.id || !payload?.parameters) {
      return res.status(400).json({ error: "Missing payload.id or payload.parameters" });
    }

    const session = getSession(req);
    if (!session) return res.status(401).json({ error: "Login required. Call /api/init with credentials." });

    // Validate/reuse session only (no creds here). If expired => throws.
    const refreshed = await ensureAuthed(session, null);
    setSession(res, refreshed);

    const data = await callBiResults(refreshed, payload);
    return res.status(200).json(data);
  } catch (e) {
    const msg = e?.message || String(e);
    const status = /Not authenticated|login required|Login required/i.test(msg) ? 401 : 500;
    return res.status(status).json({ error: msg });
  }
}
