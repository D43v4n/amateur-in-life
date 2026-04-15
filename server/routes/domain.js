const express   = require('express');
const router    = express.Router();
const vt        = require('../services/virustotal');
const shodan    = require('../services/shodan');
const threatfox = require('../services/threatfox');

function isValidDomain(d) {
  return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(d);
}

// ── Veredicto consolidado ──────────────────────────────────────
// VT es fuente primaria con umbral de engines.
// ThreatFox y Shodan solo escalan, nunca reducen.
function consolidateVerdict(vtData, shData, tfData) {
  const hasVT = vtData && !vtData.error;
  const hasTF = tfData && !tfData.error;
  const hasSH = shData && !shData.error;

  // Sin datos de ninguna fuente → no podemos concluir
  if (!hasVT && !hasTF && !hasSH) return 'unknown';

  // ── 1. VT como fuente primaria ─────────────────────────────
  let verdict = 'unknown';
  if (hasVT) {
    const mal = vtData.malicious || 0;
    const sus = vtData.suspicious || 0;
    if      (mal >= 3) verdict = 'malicious'; // consenso claro (≥3 engines)
    else if (mal >= 1) verdict = 'suspect';   // detección aislada
    else if (sus >= 3) verdict = 'suspect';   // múltiples engines sospechosos
    else               verdict = 'clean';
  }

  // ── 2. ThreatFox escala hacia arriba ──────────────────────
  if (hasTF && tfData.matches?.length > 0) {
    const maxConf = Math.max(...tfData.matches.map(m => m.confidence || 0), 0);
    if      (maxConf >= 75 && verdict !== 'malicious') verdict = 'malicious';
    else if (maxConf >  0  && (verdict === 'clean' || verdict === 'unknown')) verdict = 'suspect';
  }

  // ── 3. Shodan escala si hay CVEs conocidos ─────────────────
  if (hasSH && shData.vulns?.length > 0 && verdict === 'clean') {
    verdict = 'suspect';
  }

  return verdict;
}

router.post('/check', async (req, res) => {
  const { domains = [] } = req.body;
  if (!Array.isArray(domains) || !domains.length)
    return res.status(400).json({ error: 'Se requiere un array de dominios.' });
  if (domains.length > 20)
    return res.status(400).json({ error: 'Máximo 20 dominios.' });
  const invalid = domains.filter(d => !isValidDomain(d));
  if (invalid.length)
    return res.status(400).json({ error: `Dominios inválidos: ${invalid.join(', ')}` });

  const results = await Promise.all(domains.map(async (domain) => {
    const [vtRes, shRes, tfRes] = await Promise.allSettled([
      process.env.VIRUSTOTAL_API_KEY ? vt.checkDomain(domain) : Promise.resolve(null),
      process.env.SHODAN_API_KEY     ? shodan.checkDomain(domain) : Promise.resolve(null),
      threatfox.checkDomain(domain),
    ]);

    const vtData = vtRes.status === 'fulfilled' ? vtRes.value : null;
    const shData = shRes.status === 'fulfilled' ? shRes.value : null;
    const tfData = tfRes.status === 'fulfilled' ? tfRes.value : null;

    const verdict = consolidateVerdict(vtData, shData, tfData);

    // Score VT: % de motores que detectan
    const vtScore = vtData && !vtData.error && vtData.total
      ? Math.round((vtData.malicious / vtData.total) * 100) : null;

    const summary = {
      score:            vtScore,
      engines_malicious:vtData?.malicious ?? null,
      engines_suspicious:vtData?.suspicious ?? null,
      engines_total:    vtData?.total ?? null,
      community_score:  vtData?.reputation ?? null,
      country:          shData?.country || vtData?.country || null,
      org:              shData?.org || null,
      ports:            shData?.ports || [],
      vulns:            shData?.vulns || [],
      threatfox_family: tfData?.matches?.[0]?.malwareFamily || null,
    };

    const sources = [
      vtData ? { source: 'VirusTotal', found: !vtData.error, verdict: vtData.verdict,
        link: `https://www.virustotal.com/gui/domain/${domain}` } : null,
      shData ? { source: 'Shodan', found: !shData.error, verdict: shData.verdict,
        link: `https://www.shodan.io/search?query=${domain}` } : null,
      tfData ? { source: 'ThreatFox', found: (tfData.matches?.length > 0), verdict: tfData.verdict,
        link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${domain}` } : null,
    ].filter(Boolean);

    const errors = [vtData, shData, tfData]
      .filter(s => s?.error)
      .map(s => ({ source: s.source, message: s.error }));

    return { domain, verdict, summary, engines_detail: vtData?.engines_detail || null, sources, errors };
  }));

  res.json({ results });
});

module.exports = router;
