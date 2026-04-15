const express   = require('express');
const router    = express.Router();
const vt        = require('../services/virustotal');
const shodan    = require('../services/shodan');
const threatfox = require('../services/threatfox');
const abuseipdb = require('../services/abuseipdb');

// ── Veredicto consolidado para IPs ────────────────────────────
// VT primario con umbral. ThreatFox y Shodan solo escalan.
function consolidateVerdict(vtData, shData, tfData, abData) {
  const hasVT = vtData && !vtData.error;
  const hasTF = tfData && !tfData.error;
  const hasSH = shData && !shData.error;
  const hasAB = abData && !abData.error;

  if (!hasVT && !hasTF && !hasSH && !hasAB) return 'unknown';

  // ── 1. VT primario con umbral ──────────────────────────────
  let verdict = 'unknown';
  if (hasVT) {
    const mal = vtData.malicious || 0;
    const sus = vtData.suspicious || 0;
    if      (mal >= 3) verdict = 'malicious'; // consenso claro
    else if (mal >= 1) verdict = 'suspect';   // detección aislada
    else if (sus >= 3) verdict = 'suspect';   // múltiples sospechosos
    else               verdict = 'clean';
  }

  // ── 2. ThreatFox escala ────────────────────────────────────
  if (hasTF && tfData.matches?.length > 0) {
    const maxConf = Math.max(...tfData.matches.map(m => m.confidence || 0), 0);
    if      (maxConf >= 75 && verdict !== 'malicious') verdict = 'malicious';
    else if (maxConf >  0  && (verdict === 'clean' || verdict === 'unknown')) verdict = 'suspect';
  }

  // ── 3. Shodan escala si hay CVEs conocidos ─────────────────
  if (hasSH && shData.vulns?.length > 0 && (verdict === 'clean' || verdict === 'unknown')) {
    verdict = 'suspect';
  }

  // ── 4. AbuseIPDB escala por score de abuso ─────────────────
  // >= 80: señal fuerte de IP activamente maliciosa
  // >= 25: actividad sospechosa reportada por la comunidad
  if (hasAB) {
    if      (abData.confidence >= 80 && verdict !== 'malicious') verdict = 'malicious';
    else if (abData.confidence >= 25 && (verdict === 'clean' || verdict === 'unknown')) verdict = 'suspect';
  }

  return verdict;
}

function isPublicIP(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  if (parts.some(p => p > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 127) return false;
  return true;
}

router.post('/check', async (req, res) => {
  const { ips = [] } = req.body;
  if (!Array.isArray(ips) || !ips.length)
    return res.status(400).json({ error: 'Se requiere un array de IPs.' });
  if (ips.length > 20)
    return res.status(400).json({ error: 'Máximo 20 IPs.' });
  const invalid = ips.filter(ip => !isPublicIP(ip));
  if (invalid.length)
    return res.status(400).json({ error: `IPs inválidas o privadas: ${invalid.join(', ')}` });

  const results = await Promise.all(ips.map(async (ip) => {
    const [vtRes, shRes, tfRes, abRes] = await Promise.allSettled([
      process.env.VIRUSTOTAL_API_KEY  ? vt.checkIP(ip)        : Promise.resolve(null),
      process.env.SHODAN_API_KEY      ? shodan.checkIP(ip)     : Promise.resolve(null),
      threatfox.checkIP(ip),
      process.env.ABUSEIPDB_API_KEY   ? abuseipdb.checkIP(ip) : Promise.resolve(null),
    ]);

    const vtData = vtRes.status === 'fulfilled' ? vtRes.value : null;
    const shData = shRes.status === 'fulfilled' ? shRes.value : null;
    const tfData = tfRes.status === 'fulfilled' ? tfRes.value : null;
    const abData = abRes.status === 'fulfilled' ? abRes.value : null;

    const verdict = consolidateVerdict(vtData, shData, tfData, abData);

    const vtScore = vtData && !vtData.error && vtData.total
      ? Math.round((vtData.malicious / vtData.total) * 100) : null;

    const summary = {
      score:             vtScore,
      engines_malicious: vtData?.malicious ?? null,
      engines_suspicious:vtData?.suspicious ?? null,
      engines_total:     vtData?.total ?? null,
      community_score:   vtData?.reputation ?? null,
      country:           shData?.country || vtData?.country || null,
      org:               shData?.org || vtData?.asOwner || null,
      isp:               shData?.isp || null,
      asn:               shData?.asn || vtData?.asn || null,
      ports:             shData?.ports || [],
      vulns:             shData?.vulns || [],
      tags:              shData?.tags || [],
      threatfox_family:  tfData?.matches?.[0]?.malwareFamily || null,
      abuse_confidence:  abData?.confidence  ?? null,
      abuse_reports:     abData?.totalReports ?? null,
      abuse_is_tor:      abData?.isTor        || false,
    };

    const sources = [
      vtData ? { source: 'VirusTotal', found: !vtData.error, verdict: vtData.verdict,
        link: `https://www.virustotal.com/gui/ip-address/${ip}` } : null,
      shData ? { source: 'Shodan', found: !shData.error, verdict: shData.verdict,
        link: `https://www.shodan.io/host/${ip}` } : null,
      tfData ? { source: 'ThreatFox', found: (tfData.matches?.length > 0), verdict: tfData.verdict,
        link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${ip}` } : null,
      abData ? { source: 'AbuseIPDB', found: !abData.error, verdict: abData.verdict,
        link: `https://www.abuseipdb.com/check/${ip}` } : null,
    ].filter(Boolean);

    const errors = [vtData, shData, tfData, abData]
      .filter(s => s?.error)
      .map(s => ({ source: s.source, message: s.error }));

    return { ip, verdict, summary, engines_detail: vtData?.engines_detail || null, sources, errors };
  }));

  res.json({ results });
});

module.exports = router;
