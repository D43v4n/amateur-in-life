// services/whois.js
// Usa RDAP bootstrap de IANA — estándar oficial, sin dependencias externas
const axios = require('axios');
const https = require('https');
const dns   = require('dns').promises;

const agent = new https.Agent({ rejectUnauthorized: false });

async function resolveIP(domain) {
  try {
    const addrs = await dns.resolve4(domain);
    return addrs[0] || null;
  } catch { return null; }
}

async function getIPLocation(ip) {
  try {
    const { data } = await axios.get(`https://ipwho.is/${ip}`, { httpsAgent: agent, timeout: 5000 });
    if (!data.success) return null;
    return {
      ip,
      country:      data.country      || null,
      country_code: data.country_code || null,
      region:       data.region       || null,
      city:         data.city         || null,
      lat:          data.latitude     || null,
      lon:          data.longitude    || null,
      timezone:     data.timezone?.id || null,
      isp:          data.connection?.isp || null,
      org:          data.connection?.org || null,
      asn:          data.connection?.asn ? `AS${data.connection.asn}` : null,
    };
  } catch { return null; }
}

// IANA RDAP bootstrap: nos dice qué servidor RDAP usar para cada TLD
async function getRdapServer(tld) {
  try {
    const { data } = await axios.get(
      'https://data.iana.org/rdap/dns.json',
      { timeout: 5000 }
    );
    const entry = data.services.find(([tlds]) => tlds.includes(tld.toLowerCase()));
    return entry ? entry[1][0] : null;
  } catch {
    return null;
  }
}

function extractVcard(entity, field) {
  return entity?.vcardArray?.[1]?.find(f => f[0] === field)?.[3] || null;
}

function getEvent(events = [], type) {
  return events.find(e => e.eventAction === type)?.eventDate?.split('T')[0] || null;
}

async function queryRdap(domain) {
  const tld = domain.split('.').pop();
  const server = await getRdapServer(tld);
  const base = server || 'https://rdap.verisign.com/com/v1/'; // fallback para .com

  const url = `${base}domain/${domain}`;
  const { data } = await axios.get(url, { timeout: 6000 });

  const registrar   = data.entities?.find(e => e.roles?.includes('registrar'));
  const registrant  = data.entities?.find(e => e.roles?.includes('registrant'));
  const adminEntity = data.entities?.find(e => e.roles?.includes('administrative'));

  const nameservers = (data.nameservers || [])
    .map(ns => ns.ldhName?.toLowerCase()).filter(Boolean).join(', ') || '—';

  const status = (data.status || []).join(', ') || '—';

  return {
    domain,
    registrar:         extractVcard(registrar, 'fn') || registrar?.handle || '—',
    registrant_name:   extractVcard(registrant, 'fn') || 'REDACTED (GDPR)',
    registrant_org:    extractVcard(registrant, 'org') || extractVcard(adminEntity, 'org') || '—',
    registrant_country:extractVcard(registrant, 'adr')?.[6] || '—',
    created:           getEvent(data.events, 'registration'),
    updated:           getEvent(data.events, 'last changed'),
    expires:           getEvent(data.events, 'expiration'),
    nameservers,
    status,
    dnssec:            data.secureDNS?.delegationSigned ? 'Firmado' : 'No firmado',
    rdapUrl:           `https://www.iana.org/whois?q=${domain}`,
  };
}

// Fallback: whoisjsonapi público
async function queryWhoisJson(domain) {
  const { data } = await axios.get(
    `https://whoisjsonapi.com/v1/${domain}`,
    { timeout: 6000 }
  );
  const r = data;
  return {
    domain,
    registrar:         r.registrar?.name || '—',
    registrant_name:   r.registrant?.name || 'REDACTED (GDPR)',
    registrant_org:    r.registrant?.organization || '—',
    registrant_country:r.registrant?.country || '—',
    created:           r.created_date?.split('T')[0] || null,
    updated:           r.updated_date?.split('T')[0] || null,
    expires:           r.expiration_date?.split('T')[0] || null,
    nameservers:       (r.name_servers || []).join(', ') || '—',
    status:            Array.isArray(r.status) ? r.status.join(', ') : r.status || '—',
    dnssec:            r.dnssec || '—',
    rdapUrl:           `https://www.iana.org/whois?q=${domain}`,
  };
}

async function lookup(domain) {
  const ip = await resolveIP(domain);
  const ip_location = ip ? await getIPLocation(ip) : null;

  try {
    const whoisData = await queryRdap(domain);
    return { ...whoisData, ip_location };
  } catch (err1) {
    try {
      const whoisData = await queryWhoisJson(domain);
      return { ...whoisData, ip_location };
    } catch (err2) {
      return { domain, error: `No se pudo obtener WHOIS: ${err1.message}`, ip_location };
    }
  }
}

module.exports = { lookup };
