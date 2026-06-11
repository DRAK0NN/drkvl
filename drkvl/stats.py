import re
import subprocess

from .util import have

API = "127.0.0.1:10085"

_STAT_LINE = re.compile(r'"name":\s*"([^"]+)"\s*,\s*"value":\s*"?(-?\d+)"?')


def query() -> dict[str, int]:
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
    s = query()
    up = s.get("outbound>>>proxy>>>traffic>>>uplink", 0)
    dn = s.get("outbound>>>proxy>>>traffic>>>downlink", 0)
    return up, dn
