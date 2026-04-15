// services/abuseipdb.js
const axios = require('axios');
const https = require('https');

const BASE  = 'https://api.abuseipdb.com/api/v2';
const agent = new https.Agent({ rejectUnauthorized: false });

async function checkIP(ip) {
  try {
    const { data } = await axios.get(`${BASE}/check`, {
      params:  { ipAddress: ip, maxAgeInDays: 90 },
      headers: {
        'Key':    process.env.ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
      },
      httpsAgent: agent,
      timeout:    8000,
    });

    const d      = data.data;
    const score  = d.abuseConfidenceScore || 0;
    const verdict =
      score >= 80 ? 'malicious' :
      score >= 25 ? 'suspect'   : 'clean';

    return {
      source:       'AbuseIPDB',
      ip,
      verdict,
      confidence:   score,
      totalReports: d.totalReports      || 0,
      distinctUsers:d.numDistinctUsers  || 0,
      isWhitelisted:d.isWhitelisted     || false,
      isTor:        d.isTor             || false,
      usageType:    d.usageType         || '—',
      isp:          d.isp               || '—',
      countryCode:  d.countryCode       || '—',
      lastReported: d.lastReportedAt?.split('T')[0] || null,
    };
  } catch (err) {
    return {
      source: 'AbuseIPDB',
      ip,
      error: err.response?.data?.errors?.[0]?.detail || err.message,
    };
  }
}

module.exports = { checkIP };
