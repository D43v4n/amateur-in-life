PORT_APP_ID_MAP = {
    20:    ["ftp"],
    21:    ["ftp"],
    22:    ["ssh"],
    23:    ["telnet"],
    25:    ["smtp"],
    53:    ["dns"],
    67:    ["dhcp"],
    68:    ["dhcp"],
    69:    ["tftp"],
    80:    ["web-browsing"],
    88:    ["kerberos"],
    110:   ["pop3"],
    119:   ["nntp"],
    123:   ["ntp"],
    135:   ["msrpc"],
    137:   ["netbios-ns"],
    138:   ["netbios-dg"],
    139:   ["netbios-ss"],
    143:   ["imap"],
    161:   ["snmp"],
    162:   ["snmp-trap"],
    389:   ["ldap"],
    443:   ["ssl", "web-browsing"],
    445:   ["smb", "ms-ds-replication"],
    465:   ["smtps"],
    500:   ["ike"],
    514:   ["syslog"],
    587:   ["smtp"],
    636:   ["ldap"],
    993:   ["imaps"],
    995:   ["pop3s"],
    1433:  ["ms-sql-db"],
    1521:  ["oracle-db"],
    1723:  ["pptp"],
    3306:  ["mysql"],
    3389:  ["msrdp"],
    4443:  ["ssl"],
    5060:  ["sip"],
    5061:  ["sip"],
    5432:  ["postgresql"],
    5900:  ["vnc-base"],
    6379:  ["redis"],
    8080:  ["web-browsing"],
    8443:  ["ssl"],
    8888:  ["web-browsing"],
    9200:  ["elasticsearch"],
    9300:  ["elasticsearch"],
    27017: ["mongodb"],
}


def get_suggestions(puerto_str):
    suggestions = set()
    puerto_str = puerto_str.strip().lower()
    if not puerto_str or puerto_str == "any":
        return []
    for part in puerto_str.split(","):
        part = part.strip()
        if "-" in part:
            sub = part.split("-")
            try:
                p1, p2 = int(sub[0]), int(sub[1])
                for p in range(p1, min(p2 + 1, p1 + 200)):
                    if p in PORT_APP_ID_MAP:
                        suggestions.update(PORT_APP_ID_MAP[p])
            except (ValueError, IndexError):
                pass
        else:
            try:
                p = int(part)
                if p in PORT_APP_ID_MAP:
                    suggestions.update(PORT_APP_ID_MAP[p])
            except ValueError:
                pass
    return sorted(list(suggestions))
