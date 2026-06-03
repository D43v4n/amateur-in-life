const express = require('express');
const router  = express.Router();
const axios   = require('axios');
const https   = require('https');
const PORTS   = require('../data/ports');
const { isValidPort } = require('../utils/validators');

const agent = new https.Agent({ rejectUnauthorized: false });

async function getShodanPortCount(port) {
  if (!process.env.SHODAN_API_KEY) return null;
  try {
    const { data } = await axios.get('https://api.shodan.io/shodan/host/count', {
      params: { key: process.env.SHODAN_API_KEY, query: `port:${port}` },
      httpsAgent: agent,
      timeout: 5000,
    });
    return data.total ?? null;
  } catch { return null; }
}

router.post('/lookup', async (req, res) => {
  const { ports = [] } = req.body;
  if (!Array.isArray(ports) || !ports.length)
    return res.status(400).json({ error: 'Se requiere un array de puertos.' });
  if (ports.length > 20)
    return res.status(400).json({ error: 'Máximo 20 puertos por consulta.' });

  const invalid = ports.filter(p => !isValidPort(p));
  if (invalid.length)
    return res.status(400).json({ error: `Puertos inválidos: ${invalid.join(', ')}. Rango válido: 1-65535.` });

  const results = await Promise.all(ports.map(async (p) => {
    const num  = parseInt(p, 10);
    const info = PORTS[num] || null;
    const exposure = await getShodanPortCount(num);

    if (!info) {
      return {
        port:        num,
        known:       false,
        name:        'Puerto no registrado',
        proto:       [],
        category:    'unknown',
        security:    'info',
        description: 'Este puerto no tiene asignación estándar conocida. Puede ser una aplicación personalizada, efímero, o potencialmente sospechoso.',
        apps:        [],
        warning:     null,
        secure_alt:  null,
        posture:     'restrict',
        malware:     false,
        exfil:       false,
        note:        null,
        exposure,
        shodan_link: `https://www.shodan.io/search?query=port:${num}`,
      };
    }

    return {
      port:        num,
      known:       true,
      name:        info.name,
      proto:       info.proto,
      category:    info.category,
      security:    info.security,
      description: info.description,
      apps:        info.apps || [],
      warning:     info.warning || null,
      secure_alt:  info.secure_alt || null,
      posture:     info.posture,
      malware:     info.malware || false,
      exfil:       info.exfil || false,
      note:        info.note || null,
      exposure,
      shodan_link: `https://www.shodan.io/search?query=port:${num}`,
    };
  }));

  res.json({ results });
});

module.exports = router;
