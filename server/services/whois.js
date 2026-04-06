// services/whois.js
// Usa RDAP bootstrap de IANA — estándar oficial, sin dependencias externas
const axios = require('axios');

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
  // Intenta RDAP primero, luego whoisjsonapi como fallback
  try {
    return await queryRdap(domain);
  } catch (err1) {
    try {
      return await queryWhoisJson(domain);
    } catch (err2) {
      return {
        domain,
        error: `No se pudo obtener WHOIS: ${err1.message}`,
      };
    }
  }
}

module.exports = { lookup };
