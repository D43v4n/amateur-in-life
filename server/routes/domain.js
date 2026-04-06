const express   = require('express');
const router    = express.Router();
const vt        = require('../services/virustotal');
const shodan    = require('../services/shodan');
const threatfox = require('../services/threatfox');

function isValidDomain(d) {
  return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(d);
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

    // Veredicto consolidado
    const verdicts = [vtData, shData, tfData].filter(Boolean).map(s => s.verdict);
    const verdict =
      verdicts.includes('malicious') ? 'malicious' :
      verdicts.includes('suspect')   ? 'suspect'   : 'clean';

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
      shData ? { source: 'Shodan', found: !shData.error,
        link: `https://www.shodan.io/search?query=${domain}` } : null,
      tfData ? { source: 'ThreatFox', found: (tfData.matches?.length > 0),
        link: tfData.matches?.length ? `https://threatfox.abuse.ch/browse.php?search=ioc%3A${domain}` : null } : null,
    ].filter(Boolean);

    const errors = [vtData, shData, tfData]
      .filter(s => s?.error)
      .map(s => ({ source: s.source, message: s.error }));

    return { domain, verdict, summary, sources, errors };
  }));

  res.json({ results });
});

module.exports = router;
