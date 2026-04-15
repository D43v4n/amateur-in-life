# 🔵 EZWatch OSINT

Plataforma de inteligencia para Blue Team. Verifica reputación de dominios, IPs, hashes y datos WHOIS consultando múltiples fuentes OSINT en paralelo.

## Fuentes integradas

| Fuente      | Dominios | IPs | Hashes | Key requerida |
|-------------|:--------:|:---:|:------:|:-------------:|
| VirusTotal  | ✅       | ✅  | ✅     | Sí (gratis)   |
| Shodan      | ✅       | ✅  | —      | Sí (gratis)   |
| ThreatFox   | ✅       | ✅  | ✅     | No (pública)  |
| RDAP/WHOIS  | ✅       | —   | —      | No (pública)  |

## Instalación rápida

### 1. Requisitos
- Node.js v18 o superior
- npm

### 2. Clonar e instalar dependencias

```bash
cd bluewatch
npm install
```

### 3. Configurar API keys

```bash
cp .env.example .env
```

Edita `.env` y pega tus keys:

```
VIRUSTOTAL_API_KEY=tu_key_aqui
SHODAN_API_KEY=tu_key_aqui
```

**¿Dónde consigo las keys?**
- VirusTotal: https://www.virustotal.com/gui/my-apikey (cuenta gratis → 4 req/min)
- Shodan: https://account.shodan.io/ (cuenta gratis → 1 req/seg)

### 4. Iniciar el servidor

```bash
# Producción
npm start

# Desarrollo (recarga automática)
npm run dev
```

### 5. Abrir en el navegador

```
http://localhost:3000
```

## Estructura del proyecto

```
bluewatch/
├── server/
│   ├── index.js              # Servidor Express principal
│   ├── routes/
│   │   ├── domain.js         # POST /api/domain/check
│   │   ├── ip.js             # POST /api/ip/check
│   │   ├── hash.js           # POST /api/hash/check
│   │   └── whois.js          # POST /api/whois/lookup
│   └── services/
│       ├── virustotal.js     # Integración VirusTotal API v3
│       ├── shodan.js         # Integración Shodan API
│       ├── threatfox.js      # Integración ThreatFox (pública)
│       └── whois.js          # Lookup RDAP/WHOIS
├── public/
│   └── index.html            # Frontend (servido por Express)
├── .env.example              # Template de variables de entorno
├── .gitignore
└── package.json
```

## API Reference

### POST /api/domain/check
```json
{ "domains": ["google.com", "suspicious.net"] }
```

### POST /api/ip/check
```json
{ "ips": ["8.8.8.8", "185.220.101.1"] }
```

### POST /api/hash/check
```json
{ "hashes": ["d41d8cd98f00b204e9800998ecf8427e"] }
```

### POST /api/whois/lookup
```json
{ "domains": ["example.com"] }
```

## Notas de seguridad

- Las API keys se leen desde variables de entorno (`.env`), nunca se exponen al frontend
- Rate limiting: 60 requests/minuto por IP
- Validación de IPs: rechaza rangos privados (RFC 1918) y loopback
- **No subas el archivo `.env` a git** (ya está en `.gitignore`)
