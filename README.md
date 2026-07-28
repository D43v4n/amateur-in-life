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

## Módulo de puertos

`POST /api/ports/lookup` responde con datos de dos fuentes:

1. **Base curada** (`server/data/ports.js`) — contexto de seguridad para Blue Team (riesgo, posture, malware/exfil, alternativas seguras) sobre puertos comúnmente relevantes.
2. **Fallback nmap-services** (`server/data/nmap-services.js`) — si el puerto no está en la base curada, se busca en la base de datos del proyecto Nmap (`nmap-services`) y se devuelve el nombre de servicio observado y la frecuencia con la que Nmap lo encontró abierto en internet. Esto **no es un veredicto de seguridad**, es una referencia para que el operador confirme el *business justification* del puerto.

## Licencia

BlueWatch OSINT está licenciado bajo la **Nmap Public Source License (NPSL) v0.95** — ver [`LICENSE`](LICENSE). Se usa esta licencia (en vez de una permisiva tipo MIT) porque el proyecto incorpora datos derivados de la base `nmap-services` del proyecto Nmap, lo cual, según la NPSL, obliga a que el proyecto completo se distribuya bajo estos mismos términos (GPLv2 + adiciones de la NPSL). Atribución: `nmap-services` es (C) 1996-2025 Nmap Software LLC / Insecure.Com LLC — [nmap.org](https://nmap.org/).
