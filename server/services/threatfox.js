// services/threatfox.js — Abuse.ch ThreatFox API
const axios = require('axios');

const BASE = 'https://threatfox-api.abuse.ch/api/v1/';

function headers() {
  const key = process.env.THREATFOX_API_KEY;
  // Auth-Key header desbloquea rate limits más altos y endpoints premium
  return key
    ? { 'Content-Type': 'application/json', 'Auth-Key': key }
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

function buildResult(identifier, field, data) {
  if (data.query_status === 'no_result') {
    return { source: 'ThreatFox', [field]: identifier, verdict: 'clean', matches: [] };
  }
  if (data.query_status === 'no_auth') {
    return { source: 'ThreatFox', [field]: identifier, error: 'Auth-Key inválida o faltante' };
  }
  const matches = (data.data || []).map(parseIOC);
  // Confidence >= 75 → malicious, menor → suspect
  const maxConf  = Math.max(...matches.map(m => m.confidence || 0), 0);
  const verdict  = matches.length === 0 ? 'clean'
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
