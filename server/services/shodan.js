// services/shodan.js
const axios = require('axios');
const https = require('https');
const dns   = require('dns').promises;

const BASE        = 'https://api.shodan.io';
const INTERNETDB  = 'https://internetdb.shodan.io';
const agent       = new https.Agent({ rejectUnauthorized: false });

function key() { return process.env.SHODAN_API_KEY; }

// ── InternetDB (público, sin key) ─────────────────────────────
// Devuelve: ports, hostnames, cpes, vulns, tags
async function checkIPInternetDB(ip) {
  try {
    const { data } = await axios.get(`${INTERNETDB}/${ip}`, { httpsAgent: agent, timeout: 5000 });
    const vulns = data.vulns || [];
    const tags  = data.tags  || [];
    const DANGER_TAGS = new Set(['malware', 'botnet', 'c2', 'compromised']);
    const hasDangerTag = tags.some(t => DANGER_TAGS.has(t.toLowerCase()));
    return {
      source:    'Shodan',
      ip,
      verdict:   hasDangerTag ? 'suspect' : 'unknown',
      ports:     data.ports     || [],
      hostnames: data.hostnames || [],
      cpes:      data.cpes      || [],
      vulns,
      tags,
    };
  } catch (err) {
    if (err.response?.status === 404)
      return { source: 'Shodan', ip, verdict: 'unknown', ports: [], hostnames: [], cpes: [], vulns: [], tags: [] };
    return { source: 'Shodan', ip, error: err.message };
  }
}

// ── IP: InternetDB siempre + API completa si hay key ──────────
async function checkIP(ip) {
  if (!key()) return checkIPInternetDB(ip);

  const [fullRes, idbRes] = await Promise.allSettled([
    axios.get(`${BASE}/shodan/host/${encodeURIComponent(ip)}`, { params: { key: key() }, httpsAgent: agent, timeout: 8000 }),
    checkIPInternetDB(ip),
  ]);

  const full = fullRes.status === 'fulfilled' ? fullRes.value.data : null;
  const idb  = idbRes.status  === 'fulfilled' ? idbRes.value       : null;

  if (!full) return idb || { source: 'Shodan', ip, error: 'Sin datos disponibles' };

  const vulns     = full.vulns ? Object.keys(full.vulns) : (idb?.vulns || []);
  const ports     = full.ports     || idb?.ports     || [];
  const tags      = full.tags      || idb?.tags      || [];
  const hostnames = full.hostnames || idb?.hostnames || [];
  const cpes      = idb?.cpes || [];

  const DANGER_TAGS = new Set(['malware', 'botnet', 'c2', 'compromised']);
  const hasDangerTag = tags.some(t => DANGER_TAGS.has(t.toLowerCase()));

  const services = (full.data || []).slice(0, 10).map(s => ({
    port:    s.port,
    proto:   s.transport,
    service: s.product || s._shodan?.module || '—',
    banner:  (s.data || '').slice(0, 120),
  }));

  return {
    source:      'Shodan',
    ip,
    verdict:     hasDangerTag ? 'suspect' : 'unknown',
    country:     full.country_name || '—',
    countryCode: full.country_code || '—',
    city:        full.city         || '—',
    org:         full.org          || '—',
    isp:         full.isp          || '—',
    asn:         full.asn          || '—',
    os:          full.os           || '—',
    ports,
    vulns,
    hostnames,
    cpes,
    services,
    lastUpdate:  full.last_update  || null,
    tags,
  };
}

// ── Dominio → DNS del sistema (evita proxy), luego checkIP ───
async function checkDomain(domain) {
  try {
    let ip;
    try {
      const addrs = await dns.resolve4(domain);
      ip = addrs[0];
    } catch {
      // Fallback: DNS de Shodan si hay key
      if (key()) {
        const { data } = await axios.get(`${BASE}/dns/resolve`,
          { params: { hostnames: domain, key: key() }, httpsAgent: agent, timeout: 6000 });
        ip = data[domain];
      }
    }

    if (!ip) return { source: 'Shodan', domain, verdict: 'unknown', ports: [], hostnames: [], cpes: [], vulns: [], tags: [] };

    const result = await checkIP(ip);
    return { ...result, domain, resolvedIP: ip };
  } catch (err) {
    return { source: 'Shodan', domain, error: err.response?.data?.error || err.message };
  }
}

module.exports = { checkIP, checkDomain };
