// services/virustotal.js
const axios = require('axios');

const BASE = 'https://www.virustotal.com/api/v3';

function headers() {
  return { 'x-apikey': process.env.VIRUSTOTAL_API_KEY };
}

// ── Normaliza el resumen de análisis ──────────────────────
function parseStats(stats = {}) {
  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const total      = malicious + suspicious + harmless + undetected;
  const verdict    = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspect' : 'clean';
  return { malicious, suspicious, harmless, undetected, total, verdict };
}

// ── Agrupa engines por categoría ──────────────────────────
function parseEngines(analysisResults = {}) {
  const groups = { malicious: [], suspicious: [], harmless: [], undetected: [] };
  for (const [engine, info] of Object.entries(analysisResults)) {
    const cat = info.category;
    if (groups[cat]) {
      groups[cat].push({ engine, result: info.result });
    }
  }
  for (const cat of Object.keys(groups)) {
    groups[cat].sort((a, b) => a.engine.localeCompare(b.engine));
  }
  return groups;
}

// ── Dominio ───────────────────────────────────────────────
async function checkDomain(domain) {
  try {
    const { data } = await axios.get(
      `${BASE}/domains/${encodeURIComponent(domain)}`,
      { headers: headers() }
    );
    const attr  = data.data.attributes;
    const stats = parseStats(attr.last_analysis_stats);
    return {
      source:         'VirusTotal',
      domain,
      verdict:        stats.verdict,
      malicious:      stats.malicious,
      suspicious:     stats.suspicious,
      total:          stats.total,
      categories:     attr.categories || {},
      reputation:     attr.reputation || 0,
      lastSeen:       attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString().split('T')[0]
        : null,
      engines_detail: parseEngines(attr.last_analysis_results),
    };
  } catch (err) {
    return { source: 'VirusTotal', domain, error: err.response?.data?.error?.message || err.message };
  }
}

// ── IP ────────────────────────────────────────────────────
async function checkIP(ip) {
  try {
    const { data } = await axios.get(
      `${BASE}/ip_addresses/${encodeURIComponent(ip)}`,
      { headers: headers() }
    );
    const attr  = data.data.attributes;
    const stats = parseStats(attr.last_analysis_stats);
    return {
      source:         'VirusTotal',
      ip,
      verdict:        stats.verdict,
      malicious:      stats.malicious,
      suspicious:     stats.suspicious,
      total:          stats.total,
      country:        attr.country || '—',
      asn:            attr.asn || '—',
      asOwner:        attr.as_owner || '—',
      reputation:     attr.reputation || 0,
      engines_detail: parseEngines(attr.last_analysis_results),
    };
  } catch (err) {
    return { source: 'VirusTotal', ip, error: err.response?.data?.error?.message || err.message };
  }
}

// ── Hash ──────────────────────────────────────────────────
async function checkHash(hash) {
  try {
    const { data } = await axios.get(
      `${BASE}/files/${encodeURIComponent(hash)}`,
      { headers: headers() }
    );
    const attr  = data.data.attributes;
    const stats = parseStats(attr.last_analysis_stats);
    return {
      source:         'VirusTotal',
      hash,
      verdict:        stats.verdict,
      malicious:      stats.malicious,
      suspicious:     stats.suspicious,
      total:          stats.total,
      name:           attr.meaningful_name || attr.names?.[0] || '—',
      type:           attr.type_description || '—',
      size:           attr.size || 0,
      sha256:         attr.sha256,
      md5:            attr.md5,
      sha1:           attr.sha1,
      firstSeen:      attr.first_submission_date
        ? new Date(attr.first_submission_date * 1000).toISOString().split('T')[0]
        : null,
      lastSeen:       attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString().split('T')[0]
        : null,
      tags:           attr.tags || [],
      engines_detail: parseEngines(attr.last_analysis_results),
    };
  } catch (err) {
    return { source: 'VirusTotal', hash, error: err.response?.data?.error?.message || err.message };
  }
}

module.exports = { checkDomain, checkIP, checkHash };
