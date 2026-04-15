const express   = require('express');
const router    = express.Router();
const vt        = require('../services/virustotal');
const threatfox = require('../services/threatfox');

// ── Veredicto consolidado para hashes ─────────────────────────
// VT primario. Hash no visto por VT (total=0) → unknown, no clean.
// ThreatFox es autoritativo: un IOC de hash con alta confianza
// es evidencia directa de archivo malicioso.
function consolidateVerdict(vtData, tfData) {
  const hasVT = vtData && !vtData.error;
  const hasTF = tfData && !tfData.error;

  if (!hasVT && !hasTF) return 'unknown';

  // ── 1. VT primario ─────────────────────────────────────────
  let verdict = 'unknown';
  if (hasVT) {
    if (!vtData.total) {
      verdict = 'unknown'; // hash nunca enviado a VT
    } else {
      const mal = vtData.malicious || 0;
      const sus = vtData.suspicious || 0;
      if      (mal >= 3) verdict = 'malicious';
      else if (mal >= 1) verdict = 'suspect';
      else if (sus >= 3) verdict = 'suspect';
      else               verdict = 'clean';
    }
  }

  // ── 2. ThreatFox escala (incluso desde unknown) ───────────
  // Un hash IOC con confianza alta es evidencia directa
  if (hasTF && tfData.matches?.length > 0) {
    const maxConf = Math.max(...tfData.matches.map(m => m.confidence || 0), 0);
    if      (maxConf >= 75) verdict = 'malicious';
    else if (maxConf >  0 && verdict !== 'malicious') verdict = 'suspect';
  }

  return verdict;
}

function detectHashType(h) {
  if (/^[a-fA-F0-9]{32}$/.test(h))  return 'MD5';
  if (/^[a-fA-F0-9]{40}$/.test(h))  return 'SHA-1';
  if (/^[a-fA-F0-9]{64}$/.test(h))  return 'SHA-256';
  return null;
}

router.post('/check', async (req, res) => {
  const { hashes = [] } = req.body;
  if (!Array.isArray(hashes) || !hashes.length)
    return res.status(400).json({ error: 'Se requiere un array de hashes.' });
  if (hashes.length > 20)
    return res.status(400).json({ error: 'Máximo 20 hashes.' });
  const invalid = hashes.filter(h => !detectHashType(h));
  if (invalid.length)
    return res.status(400).json({ error: `Hashes inválidos: ${invalid.join(', ')}` });

  const results = await Promise.all(hashes.map(async (hash) => {
    const hash_type = detectHashType(hash);
    const [vtRes, tfRes] = await Promise.allSettled([
      process.env.VIRUSTOTAL_API_KEY ? vt.checkHash(hash) : Promise.resolve(null),
      threatfox.checkHash(hash),
    ]);

    const vtData = vtRes.status === 'fulfilled' ? vtRes.value : null;
    const tfData = tfRes.status === 'fulfilled' ? tfRes.value : null;

    const verdict = consolidateVerdict(vtData, tfData);

    const vtScore = vtData && !vtData.error && vtData.total
      ? Math.round((vtData.malicious / vtData.total) * 100) : null;

    const summary = {
      score:             vtScore,
      engines_malicious: vtData?.malicious ?? null,
      engines_suspicious:vtData?.suspicious ?? null,
      engines_total:     vtData?.total ?? null,
      community_score:   vtData?.reputation ?? null,
      file_name:         vtData?.name || null,
      file_type:         vtData?.type || null,
      file_size:         vtData?.size || null,
      first_seen:        vtData?.firstSeen || null,
      last_seen:         vtData?.lastSeen || null,
      tags:              vtData?.tags || [],
      threatfox_family:  tfData?.matches?.[0]?.malwareFamily || null,
    };

    const sources = [
      vtData ? { source: 'VirusTotal', found: !vtData.error && vtData.total > 0,
        verdict: vtData?.verdict || null,
        link: `https://www.virustotal.com/gui/file/${hash}` } : null,
      tfData ? { source: 'ThreatFox', found: (tfData.matches?.length > 0), verdict: tfData.verdict,
        link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${hash}` } : null,
    ].filter(Boolean);

    const errors = [vtData, tfData]
      .filter(s => s?.error)
      .map(s => ({ source: s.source, message: s.error }));

    return { hash, hash_type, verdict, summary, engines_detail: vtData?.engines_detail || null, sources, errors };
  }));

  res.json({ results });
});

module.exports = router;
