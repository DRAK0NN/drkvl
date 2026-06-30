import re
import subprocess

from . import config
from .util import have

API = f"127.0.0.1:{config.API_PORT}"

_STAT_LINE = re.compile(r'"name":\s*"([^"]+)"\s*,\s*"value":\s*"?(-?\d+)"?')


def query() -> dict[str, int]:
    """Return xray's traffic counters as a name->bytes dict (empty if unavailable)."""
    if not have("xray"):
        return {}
    r = subprocess.run(
        ["xray", "api", "statsquery", f"--server={API}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return {}
    out: dict[str, int] = {}
    for m in _STAT_LINE.finditer(r.stdout):
        try:
            out[m.group(1)] = int(m.group(2))
        except ValueError:
            continue
    return out


def proxy_traffic() -> tuple[int, int]:
    """Return ``(uplink, downlink)`` bytes for the proxy outbound."""
    s = query()
    up = s.get("outbound>>>proxy>>>traffic>>>uplink", 0)
    dn = s.get("outbound>>>proxy>>>traffic>>>downlink", 0)
    return up, dn
