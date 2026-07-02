"""Custom bypass lists imported from Amnezia-format JSON.

Amnezia exports ``[{"hostname": "...", "ip": "..."}]``. We collapse hostnames to
their registrable root (``m.mts.ru`` -> ``mts.ru``) and keep IP/CIDRs that are
not overly broad, then route them 'direct' alongside geosite:ru / geoip:ru.
"""
import ipaddress
import json
import re

from . import ownership, paths, storage

# best-effort multi-label public suffixes (not a full PSL) so we don't
# over-collapse e.g. example.com.ru -> com.ru. Covers common ru + global ones.
_MULTI_SUFFIX = {
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "edu.ru",
    "gov.ru", "int.ru", "ac.ru", "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.br", "com.tr", "com.cn", "com.ua", "com.au", "co.jp",
}

_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def root_domain(host: str) -> "str | None":
    """Collapse a hostname to its registrable root, or None if it isn't a domain.

    ``m.mts.ru`` -> ``mts.ru``; ``*.mts.ru`` -> ``mts.ru``; ``a.b.ru:443`` ->
    ``ru``-root; ``city.msk.ru`` -> ``city.msk.ru`` (msk.ru is a public suffix).
    Returns None for single-label hosts, IP literals, and bare public suffixes
    (routing e.g. ``gov.ru`` direct would send the whole suffix out untunnelled).
    """
    host = host.strip().lower().lstrip("*.").strip(".")
    host = host.split("/", 1)[0]          # drop any /path
    host = re.sub(r":\d+$", "", host)     # drop a trailing :port
    if not host or not _HOST_RE.match(host):
        return None
    try:
        ipaddress.ip_address(host)        # an IP literal is not a domain
        return None
    except ValueError:
        pass
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return None
    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_SUFFIX:
        # registrable domain sits one label above the public suffix; a bare
        # suffix (len==2) has no registrable part, so drop it.
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return last2


def filter_ip(s: str) -> "str | None":
    """Return a clean IP/CIDR string, or None if invalid or overly broad.

    Skips IPv4 broader than /16 and IPv6 broader than /32; a bare host is
    emitted without its /32 (or /128) suffix.
    """
    s = s.strip()
    if not s:
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    if net.version == 4 and net.prefixlen < 16:
        return None                       # broader than /16
    if net.version == 6 and net.prefixlen < 32:
        return None                       # broader than /32
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)   # bare host, drop the /32 (or /128)
    return str(net)


def import_file(path: str) -> dict:
    """Parse an Amnezia JSON file, extract root domains + non-broad IPs, save them.

    Returns ``{'domains': N, 'ips': M, 'skipped': K}`` where skipped counts the
    non-empty IP fields dropped for being invalid or too broad.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot read {path}: {e}")
    if not isinstance(data, list):
        raise RuntimeError("expected a JSON array of {hostname, ip} objects")

    domains: set[str] = set()
    ips: set[str] = set()
    skipped = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        host = str(entry.get("hostname") or "").strip()
        if host:
            d = root_domain(host)
            if d:
                domains.add(d)
        raw_ip = str(entry.get("ip") or "").strip()
        if raw_ip:
            net = filter_ip(raw_ip)
            if net:
                ips.add(net)
            else:
                skipped += 1

    ownership.ensure_dirs()               # create ~/.config/drkvl 0700 + chown
    save(sorted(domains), sorted(ips))
    return {"domains": len(domains), "ips": len(ips), "skipped": skipped}


def save(domains: list[str], ips: list[str]) -> None:
    """Write the domain and IP bypass lists (one entry per line)."""
    storage.write_text(paths.BYPASS_DOMAINS, "\n".join(domains) + ("\n" if domains else ""))
    storage.write_text(paths.BYPASS_IPS, "\n".join(ips) + ("\n" if ips else ""))


def _load(p) -> list[str]:
    try:
        return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]
    except OSError:
        return []


def load_domains() -> list[str]:
    """Return the custom bypass domains (empty if none imported)."""
    return _load(paths.BYPASS_DOMAINS)


def load_ips() -> list[str]:
    """Return the custom bypass IP/CIDRs (empty if none imported)."""
    return _load(paths.BYPASS_IPS)


def stats() -> tuple[int, int]:
    """Return ``(n_domains, n_ips)`` currently in the custom bypass lists."""
    return len(load_domains()), len(load_ips())


def clear() -> None:
    """Remove the custom bypass files."""
    storage.clear(paths.BYPASS_DOMAINS)
    storage.clear(paths.BYPASS_IPS)
