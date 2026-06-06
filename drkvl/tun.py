import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from . import profile
from .util import info, warn

DEV = "drkvl0"
TUN_ADDR = "10.10.0.1"
TUN_PREFIX = 16
TUN_NET = "10.10.0.0/16"
RESOLV = Path("/etc/resolv.conf")
DEFAULT_DNS = b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n"

# wireguard-quick style: force all output to consult `main` before any
# other policy rule (mihomo's 9000+, custom vpn tables, etc.).
# main holds our /32 pin for the vpn server and `default dev drkvl0`.
MAIN_RULE_PRIO = "9"

# per-server pin rule, kept as a belt-and-suspenders fallback in case
# something installs a rule with priority < 9 later.
PIN_RULE_PRIO = "100"


def _run(cmd: list[str], check: bool = False) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip() or r.stdout.strip()}")
    return r.returncode, r.stdout, r.stderr


def ip(*args: str, check: bool = True) -> None:
    _run(["ip", *args], check=check)


def default_route() -> Optional[dict]:
    rc, out, _ = _run(["ip", "-j", "route", "show", "default"])
    if rc != 0:
        return None
    try:
        items = json.loads(out)
    except json.JSONDecodeError:
        return None
    for it in items:
        if it.get("dst") == "default" and it.get("dev") != DEV:
            return it
    return None


def route_to(addr: str) -> Optional[dict]:
    rc, out, _ = _run(["ip", "-j", "route", "get", addr])
    if rc != 0:
        return None
    try:
        items = json.loads(out)
        return items[0] if items else None
    except (json.JSONDecodeError, IndexError):
        return None


def _backup_resolv() -> bool:
    try:
        data = RESOLV.read_bytes()
    except OSError:
        return False
    try:
        profile.HOME.mkdir(parents=True, exist_ok=True)
        profile.RESOLV_BAK.write_bytes(data)
        profile.chown_user(profile.RESOLV_BAK)
        return True
    except OSError:
        return False


def _write_resolv(data: bytes) -> None:
    # on nixos /etc/resolv.conf is a symlink into the read-only nix
    # store. drop the symlink and write a real file in its place.
    if RESOLV.is_symlink():
        RESOLV.unlink()
    RESOLV.write_bytes(data)


def snapshot(server_ip: str) -> dict:
    have_resolv = _backup_resolv()
    snap = {
        "default": default_route(),
        "server_route": route_to(server_ip),
        "resolv_backed_up": have_resolv,
        "server_ip": server_ip,
    }
    profile.write_json(profile.BACKUP, snap)
    return snap


def load_snapshot() -> Optional[dict]:
    return profile.read_json(profile.BACKUP)


def dev_exists() -> bool:
    rc, _, _ = _run(["ip", "link", "show", DEV])
    return rc == 0


def _del_all_default_routes() -> int:
    n = 0
    for _ in range(16):
        rc, _, _ = _run(["ip", "route", "del", "default"])
        if rc != 0:
            break
        n += 1
    return n


def _route_get(addr: str) -> Optional[dict]:
    rc, out, _ = _run(["ip", "-j", "route", "get", addr])
    if rc != 0:
        return None
    try:
        items = json.loads(out)
        return items[0] if items else None
    except (json.JSONDecodeError, IndexError):
        return None


def _del_rule_prio(prio: str) -> None:
    for _ in range(8):
        rc, _, _ = _run(["ip", "rule", "del", "priority", prio])
        if rc != 0:
            break


def _del_pin_rule() -> None:
    _del_rule_prio(PIN_RULE_PRIO)


def _add_pin_rule(server_ip: str) -> None:
    _del_pin_rule()
    ip("rule", "add", "to", f"{server_ip}/32", "lookup", "main", "priority", PIN_RULE_PRIO)


def _add_main_rule() -> None:
    _del_rule_prio(MAIN_RULE_PRIO)
    ip("rule", "add", "from", "all", "lookup", "main", "priority", MAIN_RULE_PRIO)


def _del_main_rule() -> None:
    _del_rule_prio(MAIN_RULE_PRIO)


def _dump_routing(tag: str) -> None:
    try:
        path = profile.HOME / f"routing.{tag}.txt"
        with open(path, "w") as f:
            for cmd in (["ip", "rule", "show"],
                        ["ip", "route", "show", "table", "all"]):
                f.write(f"# {' '.join(cmd)}\n")
                r = subprocess.run(cmd, capture_output=True, text=True)
                f.write(r.stdout)
                f.write("\n")
        profile.chown_user(path)
    except OSError:
        pass


def _verify_pin(server_ip: str, expect_dev: str) -> Optional[str]:
    """Return the dev that the kernel will actually use for server_ip,
    or None on lookup failure."""
    r = _route_get(server_ip)
    if not r:
        return None
    return r.get("dev")


def _wait_dev(timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if dev_exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"{DEV} did not appear after {timeout}s")


def apply_up(server_ip: str, socks_port: int) -> dict:
    if dev_exists():
        raise RuntimeError(f"{DEV} already exists. run 'drkvl emergency-off' first")

    snap = snapshot(server_ip)
    gw = snap.get("default") or {}
    gw_addr = gw.get("gateway")
    gw_dev = gw.get("dev")
    if not gw_addr or not gw_dev:
        raise RuntimeError("no default route on this host")

    info(f"installing 'from all lookup main' rule (prio {MAIN_RULE_PRIO})")
    _add_main_rule()

    info(f"starting tun2socks (creates {DEV})")
    from . import proc
    proc.start_tun2socks(DEV, socks_port)

    _wait_dev()

    info(f"assigning {TUN_ADDR}/{TUN_PREFIX}")
    ip("addr", "add", f"{TUN_ADDR}/{TUN_PREFIX}", "dev", DEV)

    info(f"bringing {DEV} up")
    ip("link", "set", DEV, "up")

    info(f"pinning route to {server_ip} via {gw_addr} dev {gw_dev}")
    ip("route", "replace", f"{server_ip}/32", "via", gw_addr, "dev", gw_dev,
       "table", "main")

    dev = _verify_pin(server_ip, gw_dev)
    if dev != gw_dev:
        warn(f"pinned route resolves via {dev!r}, expected {gw_dev!r}; "
             f"adding ip rule (policy routing likely overrides main table)")
        _add_pin_rule(server_ip)
        dev = _verify_pin(server_ip, gw_dev)
        if dev != gw_dev:
            _dump_routing("pin_failed")
            raise RuntimeError(
                f"can't pin route to {server_ip}: still resolves via {dev!r}. "
                f"see {profile.HOME}/routing.pin_failed.txt, then `ip rule show` "
                f"and `ip route show table all`"
            )

    n = _del_all_default_routes()
    info(f"removed {n} default route(s)")

    info(f"adding default via {DEV}")
    ip("route", "add", "default", "dev", DEV, "metric", "1")

    # confirm the pin still holds after the default got swapped to tun;
    # if the kernel resolves the server via drkvl0 we'd have a loop.
    final_dev = _verify_pin(server_ip, gw_dev)
    if final_dev != gw_dev:
        _dump_routing("pin_lost")
        raise RuntimeError(
            f"pinned route lost after default swap: now via {final_dev!r}. "
            f"see {profile.HOME}/routing.pin_lost.txt"
        )

    info("writing /etc/resolv.conf")
    _write_resolv(DEFAULT_DNS)

    info("stopping systemd-resolved (avoid LLMNR flood)")
    subprocess.run(["systemctl", "stop", "systemd-resolved"], check=False)

    _dump_routing("up_ok")
    return snap


def apply_down(snap: Optional[dict]) -> None:
    from . import proc
    proc.stop_tun2socks()

    _del_pin_rule()
    _del_main_rule()

    ip("route", "del", "default", "dev", DEV, check=False)
    ip("link", "set", DEV, "down", check=False)
    ip("link", "del", DEV, check=False)

    if snap:
        srv = snap.get("server_ip")
        gw = snap.get("default") or {}
        if srv:
            ip("route", "del", f"{srv}/32", check=False)
        if gw.get("gateway") and gw.get("dev"):
            # only re-add if no default exists (after tun gone)
            if not default_route():
                ip("route", "add", "default", "via", gw["gateway"], "dev", gw["dev"], check=False)

    info("starting systemd-resolved")
    subprocess.run(["systemctl", "start", "systemd-resolved"], check=False)

    if profile.RESOLV_BAK.exists():
        try:
            _write_resolv(profile.RESOLV_BAK.read_bytes())
        except OSError as e:
            warn(f"could not restore /etc/resolv.conf: {e}")


def emergency() -> None:
    from . import proc

    xr = proc.xray_running()
    t2 = proc.tun2socks_running()
    dev = dev_exists()
    snap = load_snapshot()
    bak = profile.RESOLV_BAK.exists()

    if not (xr or t2 or dev or snap or bak):
        info("nothing to clean up")
        return

    if xr:
        info("killing xray")
        proc.stop_xray()
    if t2:
        info("killing tun2socks")
        proc.stop_tun2socks()
    subprocess.run(["pkill", "-x", "xray"], check=False)
    subprocess.run(["pkill", "-x", "tun2socks"], check=False)

    if dev or snap or bak:
        info("tearing down tun and restoring routes")
        try:
            apply_down(snap)
        except Exception as e:
            warn(f"teardown step failed: {e}")

    profile.clear(proc.TUN2SOCKS_PID)
    profile.clear(profile.ACTIVE)
    profile.clear(profile.BACKUP)
    profile.clear(profile.RESOLV_BAK)
    info("done")
