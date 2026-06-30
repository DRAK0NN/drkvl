import subprocess
from typing import Optional

from .util import info, warn

# systemd units that ship a competing tun-mode proxy with their own
# policy routing. checked in this order; everything active gets stopped.
CANDIDATES = [
    "clash-verge.service",
    "clash-verge-service.service",
    "mihomo.service",
    "clash.service",
    "clash-meta.service",
]

# leftover state we wipe even if the unit is no longer running:
# mihomo / clash typically install these rules at boot and they
# survive a graceful service stop.
RULE_PRIOS = ["9000", "9001", "9002", "9010"]
TABLE = "2022"
DEV = "Mihomo"


def _systemctl(*args: str) -> int:
    r = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    return r.returncode


def _is_active(unit: str) -> bool:
    return _systemctl("is-active", "--quiet", unit) == 0


def active_units() -> list[str]:
    """Return the competing clash/mihomo systemd units that are currently active."""
    return [u for u in CANDIDATES if _is_active(u)]


def _clean_leftovers() -> None:
    for prio in RULE_PRIOS:
        for _ in range(8):
            r = subprocess.run(
                ["ip", "rule", "del", "priority", prio],
                capture_output=True,
            )
            if r.returncode != 0:
                break
    subprocess.run(["ip", "route", "flush", "table", TABLE], capture_output=True)
    subprocess.run(["ip", "link", "del", DEV], capture_output=True)


def stop_active() -> list[str]:
    """Stop competing proxy units, wipe their stale routing, and return what was stopped."""
    units = active_units()
    if not units:
        # still wipe stale rules in case the service was killed dirty.
        _clean_leftovers()
        return []
    for u in units:
        info(f"stopping conflicting proxy: {u}")
        if _systemctl("stop", u) != 0:
            warn(f"systemctl stop {u} failed")
    _clean_leftovers()
    return units


def start(units: Optional[list[str]]) -> None:
    """Restart the proxy units previously stopped by :func:`stop_active`."""
    if not units:
        return
    for u in units:
        info(f"restoring: {u}")
        if _systemctl("start", u) != 0:
            warn(f"systemctl start {u} failed")
