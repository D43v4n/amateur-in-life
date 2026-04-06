const express   = require('express');
const router    = express.Router();
const vt        = require('../services/virustotal');
const shodan    = require('../services/shodan');
const threatfox = require('../services/threatfox');

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
    const [vtRes, shRes, tfRes] = await Promise.allSettled([
      process.env.VIRUSTOTAL_API_KEY ? vt.checkIP(ip) : Promise.resolve(null),
      process.env.SHODAN_API_KEY     ? shodan.checkIP(ip) : Promise.resolve(null),
      threatfox.checkIP(ip),
    ]);

    const vtData = vtRes.status === 'fulfilled' ? vtRes.value : null;
    const shData = shRes.status === 'fulfilled' ? shRes.value : null;
    const tfData = tfRes.status === 'fulfilled' ? tfRes.value : null;

    const verdicts = [vtData, shData, tfData].filter(Boolean).map(s => s.verdict);
    const verdict =
      verdicts.includes('malicious') ? 'malicious' :
      verdicts.includes('suspect')   ? 'suspect'   : 'clean';

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
    };

    const sources = [
      vtData ? { source: 'VirusTotal', found: !vtData.error, verdict: vtData.verdict,
        link: `https://www.virustotal.com/gui/ip-address/${ip}` } : null,
      shData ? { source: 'Shodan', found: !shData.error,
        link: `https://www.shodan.io/host/${ip}` } : null,
      tfData ? { source: 'ThreatFox', found: (tfData.matches?.length > 0),
        link: tfData.matches?.length ? `https://threatfox.abuse.ch/browse.php?search=ioc%3A${ip}` : null } : null,
    ].filter(Boolean);

    const errors = [vtData, shData, tfData]
      .filter(s => s?.error)
      .map(s => ({ source: s.source, message: s.error }));

    return { ip, verdict, summary, sources, errors };
  }));

  res.json({ results });
});

module.exports = router;
