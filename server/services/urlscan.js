const axios = require('axios');
const https = require('https');

const BASE  = 'https://urlscan.io/api/v1';
const agent = new https.Agent({ rejectUnauthorized: false });

function key() { return process.env.URLSCAN_API_KEY; }
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function scan(url) {
  if (!key()) return { error: 'URLSCAN_API_KEY no configurada' };

  let uuid;
  try {
    const { data } = await axios.post(`${BASE}/scan/`,
      { url, visibility: 'public' },
      { headers: { 'API-Key': key(), 'Content-Type': 'application/json' },
        httpsAgent: agent, timeout: 10000 });
    uuid = data.uuid;
  } catch (err) {
    return { error: err.response?.data?.message || err.message };
  }

  // Poll until ready — max 12 intentos × 5s = 60s
  for (let i = 0; i < 12; i++) {
    await sleep(5000);
    try {
      const { data } = await axios.get(`${BASE}/result/${uuid}/`,
        { httpsAgent: agent, timeout: 8000 });
      return formatResult(uuid, data);
    } catch (e) {
      if (e.response?.status === 404) continue;
      return { error: `Error obteniendo resultado: ${e.message}` };
    }
  }
  return { error: 'Timeout: el escaneo tardó más de 60s. Intenta de nuevo.' };
}

function formatResult(uuid, d) {
  const v = d.verdicts?.overall || {};
  const p = d.page || {};
  const l = d.lists  || {};
  const s = d.stats  || {};
  return {
    uuid,
    screenshot:  `https://urlscan.io/screenshots/${uuid}.png`,
    resultLink:  `https://urlscan.io/result/${uuid}/`,
    score:       v.score      ?? 0,
    malicious:   v.malicious  ?? false,
    categories:  v.categories || [],
    brands:      v.brands     || [],
    page: {
      url:     p.url,
      domain:  p.domain,
      ip:      p.ip,
      country: p.country,
      server:  p.server,
    },
    ips:         (l.ips          || []).slice(0, 15),
    domains:     (l.domains      || []).slice(0, 15),
    certs:       (l.certificates || []).slice(0,  3),
    uniqIPs:     s.uniqIPs     ?? 0,
    uniqDomains: s.uniqDomains ?? 0,
    requests:    s.requests    ?? 0,
    scanTime:    d.task?.time,
  };
}

module.exports = { scan };
