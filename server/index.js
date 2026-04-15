require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const domainRoutes = require('./routes/domain');
const ipRoutes     = require('./routes/ip');
const hashRoutes   = require('./routes/hash');
const whoisRoutes  = require('./routes/whois');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Rate limit: 60 req / minuto por IP
app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Demasiadas solicitudes. Espera un momento.' }
}));

// ── Rutas API ──────────────────────────────────────────────
app.use('/api/domain', domainRoutes);
app.use('/api/ip',     ipRoutes);
app.use('/api/hash',   hashRoutes);
app.use('/api/whois',  whoisRoutes);

// Estado del servidor + keys configuradas
app.get('/api/status', (req, res) => {
  res.json({
    ok: true,
    sources: {
      virustotal: !!process.env.VIRUSTOTAL_API_KEY,
      shodan:     !!process.env.SHODAN_API_KEY,
      abuseipdb:  !!process.env.ABUSEIPDB_API_KEY,
      threatfox:  true,
    }
  });
});

// SPA fallback
app.get('*', (_, res) =>
  res.sendFile(path.join(__dirname, '../public/index.html'))
);

app.listen(PORT, () =>
  console.log(`\n🔵 BlueWatch corriendo en http://localhost:${PORT}\n`)
);
