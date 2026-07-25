"""Shared rendering for the ``list``, ``status`` and ``stats`` views.

The CLI (plain) and the interactive TUI (coloured) both build their output from
these functions, parameterised by a ``color`` flag, so the two never drift.
"""
import subprocess
import time
from datetime import datetime
from typing import Optional

from . import proc, state, storage
from .util import fmt_bytes, fmt_duration


def _c(code: str, s: str, color: bool) -> str:
    """Wrap ``s`` in an ANSI colour ``code`` when ``color`` is true, else return it as-is."""
    return f"\033[{code}m{s}\033[0m" if color else s


def connection_state() -> str:
    """Return ``'on'``, ``'partial'`` or ``'off'`` from the live processes."""
    xr, t2 = proc.xray_running(), proc.tun2socks_running()
    return "on" if (xr and t2) else ("partial" if (xr or t2) else "off")


def list_lines(color: bool = False) -> list[str]:
    """Render the saved-profile list, one line per profile (empty if none)."""
    items = storage.list_all()
    if not items:
        return []
    default = state.get_default()
    lines = []
    for i, (n, v) in enumerate(items):
        mark = "*" if n == default else " "
        sec = v.security or "none"
        tag = v.name or ""
        name = _c("36", n.ljust(24), color)
        lines.append(f"{mark} {i}  {name} {v.host}:{v.port}  {v.network}/{sec}  {tag}")
    return lines


def status_lines(color: bool = False, indent: str = "") -> list[str]:
    """Render the connection-status block as a list of lines."""
    xr, t2 = proc.xray_running(), proc.tun2socks_running()
    st = "on" if (xr and t2) else ("partial" if (xr or t2) else "off")
    st_c = (_c("32", st, color) if st == "on"
            else _c("33", st, color) if st == "partial" else st)
    lines = [
        f"{indent}state:     {st_c}",
        f"{indent}xray:      {_c('32', 'running', color) if xr else 'stopped'}",
        f"{indent}tun2socks: {_c('32', 'running', color) if t2 else 'stopped'}",
    ]
    active = state.read_active()
    if active:
        started = active.get("started")
        up = time.time() - (started or time.time())
        lines.append(f"{indent}profile:   {_c('36', active.get('name', '?'), color)}")
        lines.append(f"{indent}server:    {active.get('host')}:{active.get('port')}")
        if active.get("transport"):
            lines.append(f"{indent}transport: {active['transport']}")
        lines.append(f"{indent}uptime:    {fmt_duration(up)}")
        if started:
            lines.append(f"{indent}started:   "
                         f"{datetime.fromtimestamp(started).isoformat(timespec='seconds')}")
    return lines


def stats_line(up: int, dn: int, color: bool = False) -> str:
    """Render one up/down traffic line for the given byte counters."""
    return (f"{_c('33', '↑', color)} {fmt_bytes(up):>8}    "
            f"{_c('33', '↓', color)} {fmt_bytes(dn):>8}")


def vpn_ip(socks_port: int, timeout: int = 5) -> Optional[str]:
    """Fetch the egress IP through the local socks proxy with curl.

    Goes via the socks proxy (not the tun, which may not be fully up yet),
    is bounded by ``timeout`` seconds, and returns None on any failure so the
    caller never blocks or crashes on a missing curl / slow network.
    """
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout),
             "--socks5", f"127.0.0.1:{socks_port}", "ifconfig.me/ip"],
            capture_output=True, text=True, timeout=timeout + 2)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    ip = r.stdout.strip()
    # guard against a captive-portal / WAF HTML body sneaking in
    if not ip or len(ip) > 45 or any(c not in "0123456789abcdefABCDEF:." for c in ip):
        return None
    return ip


def vpn_ip_line(socks_port: int, color: bool = False) -> str:
    """Return a ``VPN IP: <ip>`` line (or a manual-check hint) checked via socks."""
    ip = vpn_ip(socks_port)
    if ip:
        return f"VPN IP: {_c('32', ip, color)}"
    return "VPN IP: check manually (curl ifconfig.me)"


def bypass_import_line(stats: dict, color: bool = False) -> str:
    """Render the one-line summary printed after ``bypass-import``."""
    d, i, s = stats.get("domains", 0), stats.get("ips", 0), stats.get("skipped", 0)
    return (f"custom bypass: {_c('32', '+' + str(d), color)} domains, "
            f"{_c('32', '+' + str(i), color)} IPs ({s} skipped)")


def bypass_status_lines(n_domains: int, n_ips: int, color: bool = False) -> list[str]:
    """Render the ``bypass-list`` status (a hint when nothing is imported)."""
    if not (n_domains or n_ips):
        return ["no custom bypass list — import one with 'drkvl bypass-import <file.json>'"]
    return [f"custom bypass: {_c('36', str(n_domains), color)} domains, "
            f"{_c('36', str(n_ips), color)} IPs"]


def speed_table(results, color: bool = False) -> list[str]:
    """Render speed-test Results as aligned lines: header + one row per profile.

    ``results`` are objects with name/host/port/latency_ms/status; status is
    coloured green/yellow/red for ok/timeout/error when ``color`` is set.
    """
    lines = [f"{'profile':<18} {'server':<26} {'port':>5} {'latency':>9}  status"]
    for r in results:
        lat = f"{r.latency_ms:.0f}ms" if r.latency_ms is not None else "-"
        st = (_c("32", r.status, color) if r.status == "ok"
              else _c("33", r.status, color) if r.status == "timeout"
              else _c("31", r.status, color))
        lines.append(f"{r.name:<18} {r.host:<26} {r.port:>5} {lat:>9}  {st}")
    return lines
