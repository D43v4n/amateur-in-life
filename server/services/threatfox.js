// services/threatfox.js — Abuse.ch ThreatFox API
const axios = require('axios');

const BASE = 'https://threatfox-api.abuse.ch/api/v1/';

function headers() {
  return process.env.THREATFOX_API_KEY
    ? { 'Content-Type': 'application/json', 'Auth-Key': process.env.THREATFOX_API_KEY }
    : { 'Content-Type': 'application/json' };
}

async function query(payload) {
  const { data } = await axios.post(BASE, payload, {
    headers: headers(),
    timeout: 8000,
  });
  return data;
}

function parseIOC(ioc) {
  return {
    id:            ioc.id,
    type:          ioc.ioc_type,
    value:         ioc.ioc,
    malwareFamily: ioc.malware_printable || '—',
    malwareAlias:  ioc.malware_alias || null,
    confidence:    ioc.confidence_level,
    threat_type:   ioc.threat_type_desc || null,
    firstSeen:     ioc.first_seen?.split(' ')[0] || null,
    lastSeen:      ioc.last_seen?.split(' ')[0] || null,
    tags:          ioc.tags || [],
    reporter:      ioc.reporter || '—',
    reference:     ioc.reference || null,
  };
}

// Verifica que el IOC corresponde exactamente al dominio buscado
// o a un subdominio suyo. Evita falsos positivos por substring match
// de la API (ej. buscar "with.agency" devuelve IOCs con ".agency").
function iocMatchesDomain(searchDomain, iocValue, iocType) {
  const sd  = searchDomain.toLowerCase();
  const val = iocValue.toLowerCase();
  if (iocType === 'domain') {
    return val === sd || val.endsWith('.' + sd);
  }
  if (iocType === 'url') {
    try {
      const host = new URL(val.startsWith('http') ? val : 'https://' + val).hostname;
      return host === sd || host.endsWith('.' + sd);
    } catch {
      return val.includes('://' + sd + '/') || val.includes('://' + sd + ':') || val.endsWith('://' + sd);
    }
  }
  return val === sd;
}

function buildResult(identifier, field, data) {
  if (data.query_status === 'no_result') {
    return { source: 'ThreatFox', [field]: identifier, verdict: 'clean', matches: [] };
  }
  if (data.query_status === 'no_auth') {
    return { source: 'ThreatFox', [field]: identifier, error: 'Auth-Key inválida o faltante' };
  }
  let matches = (data.data || []).map(parseIOC);

  // Para dominios: descartar IOCs que no correspondan exactamente
  // al dominio o a un subdominio suyo (la API hace substring match).
  if (field === 'domain') {
    matches = matches.filter(m => iocMatchesDomain(identifier, m.value, m.type));
  }

  const maxConf = Math.max(...matches.map(m => m.confidence || 0), 0);
  const verdict = matches.length === 0 ? 'clean'
    : maxConf >= 75 ? 'malicious' : 'suspect';
  return { source: 'ThreatFox', [field]: identifier, verdict, matches };
}

async function checkDomain(domain) {
  try {
    const data = await query({ query: 'search_ioc', search_term: domain });
    return buildResult(domain, 'domain', data);
  } catch (err) {
    return { source: 'ThreatFox', domain, error: err.message };
  }
}

async function checkIP(ip) {
  try {
    const data = await query({ query: 'search_ioc', search_term: ip });
    return buildResult(ip, 'ip', data);
  } catch (err) {
    return { source: 'ThreatFox', ip, error: err.message };
  }
}

async function checkHash(hash) {
  try {
    const data = await query({ query: 'search_ioc', search_term: hash });
    return buildResult(hash, 'hash', data);
  } catch (err) {
    return { source: 'ThreatFox', hash, error: err.message };
  }
}

module.exports = { checkDomain, checkIP, checkHash };
