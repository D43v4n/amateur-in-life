import ipaddress


def validate_ip(value):
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return True, None
    except ValueError:
        pass
    if "-" in value:
        parts = value.split("-", 1)
        try:
            ipaddress.ip_address(parts[0].strip())
            ipaddress.ip_address(parts[1].strip())
            return True, None
        except ValueError:
            pass
    try:
        ipaddress.ip_address(value)
        return True, None
    except ValueError:
        pass
    return False, f"'{value}' is not a valid IP, CIDR or range"


def validate_port(value):
    value = value.strip()
    parts = [p.strip() for p in value.split(",")]
    for part in parts:
        if "-" in part:
            sub = part.split("-")
            if len(sub) != 2:
                return False, f"Invalid port range: '{part}'"
            try:
                p1, p2 = int(sub[0]), int(sub[1])
                if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2):
                    return False, f"Out of range (1-65535): '{part}'"
            except ValueError:
                return False, f"Non-numeric port: '{part}'"
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    return False, f"Port out of range (1-65535): '{part}'"
            except ValueError:
                return False, f"Invalid port: '{part}'"
    return True, None


def get_ip_type(value):
    """Returns 'private', 'public', or None if value is invalid."""
    value = value.strip()
    base = value.split("/")[0] if "/" in value else (value.split("-")[0] if "-" in value else value)
    try:
        addr = ipaddress.ip_address(base.strip())
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "private"
        return "public"
    except ValueError:
        return None
