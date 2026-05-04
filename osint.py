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

OSINT_BLOCK_SCORE = 75


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
    Returns a dict with score/reports/country/isp/domain, or None if unavailable.
    Requires the ABUSEIPDB_API_KEY environment variable.
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
