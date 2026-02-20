export const config = { runtime: "nodejs" };

import { ensureAuthed, getSession, setSession } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  try {
    // Read existing encrypted session cookie (if any)
    const existing = getSession(req) || {};

    // Credentials come from user (frontend). If omitted, we'll attempt reuse.
    const { username, password } = req.body || {};
    const creds = username ? { username, password } : null;

    const updated = await ensureAuthed(existing, creds);

    // Store refreshed session in encrypted cookie
    setSession(res, updated);

    return res.status(200).json({ ok: true });
  } catch (e) {
    // 401 so the UI knows it's an auth issue (not "server exploded")
    return res.status(401).json({ error: e?.message || String(e) });
  }
}
