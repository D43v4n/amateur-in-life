import os

INSECURE_PORTS = {
    21:   "FTP",
    23:   "Telnet",
    25:   "SMTP (plaintext)",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh/syslog",
    873:  "rsync",
    3268: "LDAP-GC",
    5900: "VNC",
    8080: "HTTP-alt",
    8008: "HTTP-alt",
}

# ── Verdict thresholds ────────────────────────────────────────────────────
ABUSE_MALICIOUS  = 75   # AbuseIPDB confidence score >= this → malicious
ABUSE_SUSPICIOUS = 25   # AbuseIPDB confidence score >= this → suspicious

VT_MALICIOUS_ENGINES  = 3   # VirusTotal engines flagging malicious >= this → malicious
VT_SUSPICIOUS_ENGINES = 1   # VirusTotal engines flagging suspicious >= this → suspicious


def check_insecure_ports(port_str):
    """Return list of {port, name} dicts for insecure ports found in the port string."""
    found = []
    seen = set()

    for part in port_str.strip().split(","):
        part = part.strip()
        if "-" in part:
            sub = part.split("-", 1)
            try:
                p1, p2 = int(sub[0].strip()), int(sub[1].strip())
                for bad in sorted(INSECURE_PORTS):
                    if p1 <= bad <= p2 and bad not in seen:
                        found.append({"port": bad, "name": INSECURE_PORTS[bad]})
                        seen.add(bad)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if p in INSECURE_PORTS and p not in seen:
                    found.append({"port": p, "name": INSECURE_PORTS[p]})
                    seen.add(p)
            except ValueError:
                pass

    return found


def get_base_ip(ip_str):
    """Extract the representative IP from a CIDR, range, or plain address."""
    ip_str = ip_str.strip()
    if "/" in ip_str:
        return ip_str.split("/")[0].strip()
    if "-" in ip_str:
        return ip_str.split("-")[0].strip()
    return ip_str


def check_abuseipdb(ip):
    """
    Query AbuseIPDB for the given IP.
    Returns a dict or None if the key is not configured or the request fails.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None
    try:
        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "score":   d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "country": d.get("countryCode", ""),
                "isp":     d.get("isp", ""),
                "domain":  d.get("domain", ""),
            }
    except Exception:
        pass
    return None


def check_virustotal(ip):
    """
    Query VirusTotal for the given IP.
    Returns a dict or None if the key is not configured or the request fails.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        import requests
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=6,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "country":    attrs.get("country", ""),
                "as_owner":   attrs.get("as_owner", ""),
            }
    except Exception:
        pass
    return None


def get_combined_verdict(abuseipdb, virustotal):
    """
    Combine results from both services into a single verdict.
    Returns 'malicious', 'suspicious', or 'clean'.
    """
    malicious = False
    suspicious = False

    if abuseipdb:
        score = abuseipdb["score"]
        if score >= ABUSE_MALICIOUS:
            malicious = True
        elif score >= ABUSE_SUSPICIOUS:
            suspicious = True

    if virustotal:
        vt_mal = virustotal["malicious"]
        vt_sus = virustotal["suspicious"]
        if vt_mal >= VT_MALICIOUS_ENGINES:
            malicious = True
        elif vt_mal > 0 or vt_sus >= VT_SUSPICIOUS_ENGINES:
            suspicious = True

    if malicious:
        return "malicious"
    if suspicious:
        return "suspicious"
    return "clean"
