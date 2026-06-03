const express = require('express');
const router  = express.Router();
const whois   = require('../services/whois');
const { isValidDomain } = require('../utils/validators');

router.post('/lookup', async (req, res) => {
  const { domains = [] } = req.body;
  if (!Array.isArray(domains) || !domains.length)
    return res.status(400).json({ error: 'Se requiere un array de dominios.' });
  if (domains.length > 10)
    return res.status(400).json({ error: 'Máximo 10 dominios para WHOIS.' });
  const invalid = domains.filter(d => !isValidDomain(d));
  if (invalid.length)
    return res.status(400).json({ error: `Dominios inválidos: ${invalid.join(', ')}` });

  const results = await Promise.all(domains.map(d => whois.lookup(d)));
  res.json({ results });
});

module.exports = router;
