const express = require('express');
const router  = express.Router();
const urlscan = require('../services/urlscan');

router.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string')
    return res.status(400).json({ error: 'Se requiere una URL.' });
  try { new URL(url); } catch {
    return res.status(400).json({ error: 'URL inválida. Incluye el protocolo (https://...)' });
  }

  const result = await urlscan.scan(url);
  if (result.error)
    return res.status(result.error.includes('no configurada') ? 503 : 500).json(result);
  res.json(result);
});

module.exports = router;
