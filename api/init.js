// api/init.js
export const config = { runtime: "nodejs" };

import { getSession, setSession } from "./_cookieSession.js";
import { ensureAuthed } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ error: "POST required" });

  try {
    const { username, password } = req.body || {};

    const existing = getSession(req) || {};

    const updated = await ensureAuthed(existing, username ? { username, password } : null);

    setSession(res, updated);

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
}
