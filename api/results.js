import { callBiResults } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

  try {
    const payload = req.body;
    if (!payload?.id || !payload?.parameters) {
      return res.status(400).json({ error: "Missing payload.id or payload.parameters" });
    }

    const data = await callBiResults(payload);
    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: e?.message || String(e) });
  }
}
