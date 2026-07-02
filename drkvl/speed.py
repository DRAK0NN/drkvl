"""Parallel profile speed-testing for ``up --fallback`` and ``speedtest``.

Each profile gets a throwaway xray on its own socks port; we measure how fast
curl can connect through it to a known 204 endpoint, then tear the xray down.
Tests run concurrently (a small thread pool) so N profiles take roughly one
test's wall-clock, not N. stdlib only (subprocess, threading, socket).
"""
import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

from . import config
from .link import Vless
from .util import port_open

BASE_PORT = 1090
MAX_WORKERS = 10
PING_URL = "https://www.google.com/generate_204"
CONNECT_TIMEOUT = 5


@dataclass
class Result:
    """One profile's speed-test outcome."""
    name: str
    host: str
    port: int
    latency_ms: Optional[float]
    status: str            # "ok" | "timeout" | "error"


def _run_curl(prefix: list, timeout: int) -> tuple[str, Optional[float]]:
    """Run curl to the ping URL with ``prefix`` args; return (status, latency_ms).

    time_starttransfer measures the real round-trip to the server (not just the
    local handshake). status is ok / timeout / error.
    """
    try:
        r = subprocess.run(
            ["curl", *prefix, "-so", "/dev/null", "-w", "%{time_starttransfer}",
             "--connect-timeout", str(timeout), PING_URL],
            capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.SubprocessError, OSError):
        return "error", None
    if r.returncode == 28:
        return "timeout", None
    if r.returncode != 0:
        return "error", None
    try:
        return "ok", float(r.stdout.strip()) * 1000.0
    except ValueError:
        return "error", None


def _curl(socks_port: int, timeout: int = CONNECT_TIMEOUT) -> tuple[str, Optional[float]]:
    """Measure round-trip latency through the socks proxy (socks5h = proxy-side DNS)."""
    return _run_curl(["-x", f"socks5h://127.0.0.1:{socks_port}"], timeout)


def curl_direct(timeout: int = CONNECT_TIMEOUT) -> tuple[str, Optional[float]]:
    """Measure round-trip over the current default route (no proxy) — used by --full,
    where the route has been swapped to the TUN so this exercises the whole stack."""
    return _run_curl([], timeout)


def _run_xray(cfg_path: str, socks_port: int, timeout: float = 3.0):
    """Start a throwaway xray; return its Popen once socks opens, else None (killed).

    Returns early (killing the process) if xray exits before the socks port
    opens, so a bad config / dead server doesn't cost the full timeout.
    """
    try:
        p = subprocess.Popen(
            ["xray", "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        if p.poll() is not None:       # xray died (e.g. bad config)
            _kill(p)
            return None
        if port_open(socks_port):
            return p
        time.sleep(0.1)
    _kill(p)
    return None


def _kill(p) -> None:
    """Terminate a process, escalating to SIGKILL, and reap it (no zombies)."""
    try:
        p.terminate()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    except (OSError, ProcessLookupError):
        pass


def _test_one(idx: int, name: str, v: Vless) -> Result:
    """Speed-test a single profile on its own socks port (BASE_PORT + idx)."""
    socks_port = BASE_PORT + idx
    api_port = socks_port + 10000          # keep each temp xray's api port unique too
    # bypass=False + geo=False -> a geo-asset-free config; the throwaway xray
    # gets no XRAY_LOCATION_ASSET, so it must not reference any geoip/geosite .dat
    cfg = config.build(v, socks_port=socks_port, api_port=api_port,
                       bypass=False, geo=False)
    fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="drkvl-speed-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        p = _run_xray(cfg_path, socks_port)
        if p is None:
            return Result(name, v.host, v.port, None, "error")
        try:
            status, latency = _curl(socks_port)
        finally:
            _kill(p)
        return Result(name, v.host, v.port, latency, status)
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def sort_results(results: list[Result]) -> list[Result]:
    """Sort responding profiles by latency first, then timeouts/errors."""
    return sorted(results, key=lambda r: (
        r.status != "ok",
        r.latency_ms if r.latency_ms is not None else float("inf")))


def run_tests(profiles: list[tuple[str, Vless]]) -> list[Result]:
    """Speed-test all profiles in parallel; return Results sorted fastest-first."""
    results: list[Optional[Result]] = [None] * len(profiles)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(_test_one, i, name, v): i
                for i, (name, v) in enumerate(profiles)}
        for fut, i in futs.items():
            try:
                results[i] = fut.result()
            except Exception:
                name, v = profiles[i]
                results[i] = Result(name, v.host, v.port, None, "error")
    return sort_results([r for r in results if r is not None])
