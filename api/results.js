// api/results.js
export const config = { runtime: "nodejs" };

import { getSession, setSession } from "./_cookieSession.js";
import { ensureAuthed, callBiResults } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ error: "POST required" });

  try {
    const payload = req.body;

    const session = getSession(req);
    if (!session) return res.status(401).json({ error: "Login required." });

    const refreshed = await ensureAuthed(session);
    setSession(res, refreshed);

    const data = await callBiResults(refreshed, payload);
    return res.status(200).json(data);
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
}
