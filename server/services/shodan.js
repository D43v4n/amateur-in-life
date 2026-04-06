// services/shodan.js
const axios = require('axios');

const BASE = 'https://api.shodan.io';

function key() {
  return process.env.SHODAN_API_KEY;
}

// ── IP info ───────────────────────────────────────────────
async function checkIP(ip) {
  try {
    const { data } = await axios.get(
      `${BASE}/shodan/host/${encodeURIComponent(ip)}`,
      { params: { key: key() } }
    );

    const ports    = data.ports || [];
    const vulns    = data.vulns ? Object.keys(data.vulns) : [];
    const services = (data.data || []).map(s => ({
      port:    s.port,
      proto:   s.transport,
      service: s.product || s._shodan?.module || '—',
      banner:  (s.data || '').slice(0, 120),
    }));

    // Si hay CVEs conocidos → sospechoso, de lo contrario neutro
    const verdict = vulns.length > 0 ? 'suspect' : 'unknown';

    return {
      source:       'Shodan',
      ip,
      verdict,
      country:      data.country_name || '—',
      countryCode:  data.country_code || '—',
      city:         data.city || '—',
      org:          data.org || '—',
      isp:          data.isp || '—',
      asn:          data.asn || '—',
      os:           data.os || '—',
      ports,
      vulns,
      services:     services.slice(0, 10),
      lastUpdate:   data.last_update || null,
      tags:         data.tags || [],
    };
  } catch (err) {
    // 404 = IP sin historial en Shodan
    if (err.response?.status === 404) {
      return { source: 'Shodan', ip, verdict: 'unknown', error: 'Sin datos en Shodan' };
    }
    return { source: 'Shodan', ip, error: err.response?.data?.error || err.message };
  }
}

// ── Dominio → resuelve IPs y consulta cada una ─────────────
async function checkDomain(domain) {
  try {
    const { data } = await axios.get(
      `${BASE}/dns/resolve`,
      { params: { hostnames: domain, key: key() } }
    );
    const ip = data[domain];
    if (!ip) return { source: 'Shodan', domain, error: 'No se pudo resolver el dominio' };

    const result = await checkIP(ip);
    return { ...result, domain, resolvedIP: ip };
  } catch (err) {
    return { source: 'Shodan', domain, error: err.response?.data?.error || err.message };
  }
}

module.exports = { checkIP, checkDomain };
