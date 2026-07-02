import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, TypedDict

from . import ownership, paths, storage
from .util import have, info, warn


class Snapshot(TypedDict):
    """Pre-``up`` routing and DNS state, captured so ``down`` can restore it."""
    default: Optional[dict]
    server_route: Optional[dict]
    resolv: dict
    stopped_resolved: bool
    server_ip: str

DEV = "drkvl0"
TUN_ADDR = "10.10.0.1"
TUN_PREFIX = 16
TUN_NET = "10.10.0.0/16"
RESOLV = Path("/etc/resolv.conf")
DEFAULT_DNS = b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n"

# split-routing for the direct outbound: xray marks its bypass sockets
# with DIRECT_FWMARK, an ip rule sends marked traffic to DIRECT_TABLE,
# and that table holds the original gw default. avoids the drkvl0 loop
# without relying on SO_BINDTODEVICE (which doesn't honour our prio-9
# `from all lookup main` rule).
DIRECT_FWMARK = 0xDD0DE
DIRECT_TABLE = "100"
DIRECT_RULE_PRIO = "8"

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
    """Run ``ip <args>``; raise RuntimeError on failure when ``check`` is true."""
    _run(["ip", *args], check=check)


def default_route() -> Optional[dict]:
    """Return the host's non-drkvl default route as a dict, or None if absent."""
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
    """Return the route the kernel would use to reach ``addr``, or None."""
    rc, out, _ = _run(["ip", "-j", "route", "get", addr])
    if rc != 0:
        return None
    try:
        items = json.loads(out)
        return items[0] if items else None
    except (json.JSONDecodeError, IndexError):
        return None


def _write_bytes(path: Path, data: bytes) -> None:
    # drop any symlink (nixos /etc/resolv.conf points into the read-only nix
    # store) and write a real file, refusing to follow a planted symlink.
    if path.is_symlink():
        path.unlink()
    fd = os.open(str(path),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _write_resolv(data: bytes) -> None:
    _write_bytes(RESOLV, data)


def _backup_resolv() -> dict:
    """Capture how to restore /etc/resolv.conf later.

    Records the symlink target (so a nixos symlink survives), or copies the
    real file to RESOLV_BAK. Never overwrites an existing backup and never
    backs up our own placeholder, so a re-up after an unclean teardown can't
    clobber the genuine config.
    """
    try:
        if RESOLV.is_symlink():
            return {"kind": "symlink", "target": os.readlink(RESOLV)}
        data = RESOLV.read_bytes()
    except OSError:
        return {"kind": "none"}
    if data == DEFAULT_DNS:
        return {"kind": "none"}            # our own placeholder, not real config
    if paths.RESOLV_BAK.exists():
        return {"kind": "file"}            # keep the first genuine backup
    try:
        paths.HOME.mkdir(parents=True, exist_ok=True)
        _write_bytes(paths.RESOLV_BAK, data)
        ownership.chown_user(paths.RESOLV_BAK)
        return {"kind": "file"}
    except OSError:
        return {"kind": "none"}


def _restore_resolv(meta: Optional[dict]) -> None:
    meta = meta or {}
    kind = meta.get("kind")
    try:
        if kind == "symlink":
            if RESOLV.is_symlink() or RESOLV.exists():
                RESOLV.unlink()
            os.symlink(meta["target"], RESOLV)
        elif kind == "file" and paths.RESOLV_BAK.exists():
            _write_bytes(RESOLV, paths.RESOLV_BAK.read_bytes())
    except OSError as e:
        warn(f"could not restore /etc/resolv.conf: {e}")


def _check_server_ip(ip: str) -> None:
    # defence in depth: server_ip is fed to `ip route`/`ip rule`; make sure it
    # is a plain IPv4 literal and can't be an option-like string ('-x', ...).
    try:
        socket.inet_aton(ip)
    except OSError:
        raise RuntimeError(f"refusing to route to non-IPv4 server address {ip!r}")


# --- IPv6: tun2socks is v4-only, so native IPv6 would bypass the tunnel.
#     Block all v6 egress (except loopback) for the session and undo on down.
_IP6_DROP = [
    ("OUTPUT", ["-o", "lo", "-j", "ACCEPT"]),
    ("OUTPUT", ["!", "-o", "lo", "-j", "DROP"]),
]


def _ip6t_del_all(chain: str, args: list[str]) -> None:
    for _ in range(8):
        rc, _, _ = _run(["ip6tables", "-w", "-D", chain, *args])
        if rc != 0:
            break


def block_ipv6() -> None:
    """Drop all non-loopback IPv6 egress for the session (ip6tables, or sysctl)."""
    if have("ip6tables"):
        for chain, a in _IP6_DROP:
            _ip6t_del_all(chain, a)
            _run(["ip6tables", "-w", "-A", chain, *a])
    else:
        # no ip6tables: disable the v6 stack outright for the session
        _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])


def unblock_ipv6() -> None:
    """Undo :func:`block_ipv6`, restoring normal IPv6 egress."""
    for chain, a in _IP6_DROP:
        _ip6t_del_all(chain, a)
    _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
    _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"])


def _resolved_active() -> bool:
    return subprocess.run(
        ["systemctl", "is-active", "--quiet", "systemd-resolved"],
        capture_output=True).returncode == 0


def snapshot(server_ip: str) -> Snapshot:
    """Capture and persist the current routing/DNS state before bringing up the tun."""
    snap: Snapshot = {
        "default": default_route(),
        "server_route": route_to(server_ip),
        "resolv": _backup_resolv(),
        "stopped_resolved": False,
        "server_ip": server_ip,
    }
    storage.write_json(paths.BACKUP, snap)
    return snap


def load_snapshot() -> Optional[Snapshot]:
    """Return the persisted pre-up snapshot, or None if there is none."""
    return storage.read_json(paths.BACKUP)


def dev_exists() -> bool:
    """Return whether the drkvl0 tun device currently exists."""
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


_MARK_RULES = [
    # save xray's outbound mark into conntrack so reply packets can be
    # restored on the way back in. nixos rpfilter (mangle PREROUTING,
    # `fib ... validmark ...`) drops unmarked replies when their fib
    # entry sits in our side table, hence we need the mark on the
    # return path too.
    ("OUTPUT", ["-m", "mark", "--mark", hex(DIRECT_FWMARK),
                "-j", "CONNMARK", "--save-mark"]),
    ("PREROUTING", ["-m", "connmark", "--mark", hex(DIRECT_FWMARK),
                    "-j", "CONNMARK", "--restore-mark"]),
]


def _iptables_del_all(chain: str, args: list[str]) -> None:
    for _ in range(8):
        rc, _, _ = _run(["iptables", "-w", "-t", "mangle", "-D", chain, *args])
        if rc != 0:
            break


def _install_mark_rules() -> None:
    for chain, args in _MARK_RULES:
        _iptables_del_all(chain, args)
        # the PREROUTING restore-mark MUST run before nixos' rpfilter rule
        # (also in mangle PREROUTING) or SYN-ACK replies are dropped before
        # their fwmark is restored — so insert it at the top instead of -A.
        op = ["-I", chain, "1"] if chain == "PREROUTING" else ["-A", chain]
        _run(["iptables", "-w", "-t", "mangle", *op, *args], check=True)


def _remove_mark_rules() -> None:
    for chain, args in _MARK_RULES:
        _iptables_del_all(chain, args)


def _setup_direct_table(gw_addr: str, gw_dev: str) -> None:
    _run(["ip", "route", "flush", "table", DIRECT_TABLE])
    ip("route", "add", "default", "via", gw_addr, "dev", gw_dev,
       "table", DIRECT_TABLE)
    _del_rule_prio(DIRECT_RULE_PRIO)
    ip("rule", "add", "fwmark", hex(DIRECT_FWMARK), "lookup", DIRECT_TABLE,
       "priority", DIRECT_RULE_PRIO)
    _install_mark_rules()


def _teardown_direct_table() -> None:
    _remove_mark_rules()
    _del_rule_prio(DIRECT_RULE_PRIO)
    _run(["ip", "route", "flush", "table", DIRECT_TABLE])


def _dump_routing(tag: str) -> None:
    try:
        path = paths.HOME / f"routing.{tag}.txt"
        fd = os.open(str(path),
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            for cmd in (["ip", "rule", "show"],
                        ["ip", "route", "show", "table", "all"]):
                f.write(f"# {' '.join(cmd)}\n")
                r = subprocess.run(cmd, capture_output=True, text=True)
                f.write(r.stdout)
                f.write("\n")
        ownership.chown_user(path)
    except OSError:
        pass


def _verify_pin(server_ip: str) -> Optional[str]:
    """Return the dev that the kernel will actually use for server_ip,
    or None on lookup failure."""
    r = route_to(server_ip)
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


def apply_up(server_ip: str, socks_port: int) -> Snapshot:
    """Bring up the tun: pin the server route, swap the default to drkvl0,
    block IPv6, point DNS at the tunnel, and return the saved snapshot."""
    if dev_exists():
        raise RuntimeError(f"{DEV} already exists. run 'drkvl emergency-off' first")

    _check_server_ip(server_ip)
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

    dev = _verify_pin(server_ip)
    if dev != gw_dev:
        warn(f"pinned route resolves via {dev!r}, expected {gw_dev!r}; "
             f"adding ip rule (policy routing likely overrides main table)")
        _add_pin_rule(server_ip)
        dev = _verify_pin(server_ip)
        if dev != gw_dev:
            _dump_routing("pin_failed")
            raise RuntimeError(
                f"can't pin route to {server_ip}: still resolves via {dev!r}. "
                f"see {paths.HOME}/routing.pin_failed.txt, then `ip rule show` "
                f"and `ip route show table all`"
            )

    n = _del_all_default_routes()
    info(f"removed {n} default route(s)")

    info(f"adding default via {DEV}")
    ip("route", "add", "default", "dev", DEV, "metric", "1")

    info(f"setting up direct table {DIRECT_TABLE} via {gw_addr} dev {gw_dev} "
         f"(fwmark {hex(DIRECT_FWMARK)} -> prio {DIRECT_RULE_PRIO})")
    _setup_direct_table(gw_addr, gw_dev)

    # confirm the pin still holds after the default got swapped to tun;
    # if the kernel resolves the server via drkvl0 we'd have a loop.
    final_dev = _verify_pin(server_ip)
    if final_dev != gw_dev:
        _dump_routing("pin_lost")
        raise RuntimeError(
            f"pinned route lost after default swap: now via {final_dev!r}. "
            f"see {paths.HOME}/routing.pin_lost.txt"
        )

    # tun2socks is IPv4-only; block native IPv6 egress so it can't leak.
    info("blocking IPv6 egress (tun2socks is IPv4-only)")
    block_ipv6()

    info("writing /etc/resolv.conf")
    _write_resolv(DEFAULT_DNS)

    if _resolved_active():
        info("stopping systemd-resolved (avoid LLMNR flood)")
        subprocess.run(["systemctl", "stop", "systemd-resolved"], check=False)
        snap["stopped_resolved"] = True
        storage.write_json(paths.BACKUP, snap)

    _dump_routing("up_ok")
    return snap


def apply_down(snap: Optional[Snapshot]) -> None:
    """Reverse :func:`apply_up`, restoring routes, IPv6, DNS and resolv.conf."""
    from . import proc
    proc.stop_tun2socks()

    unblock_ipv6()
    _del_pin_rule()
    _del_main_rule()
    _teardown_direct_table()

    ip("route", "del", "default", "dev", DEV, check=False)
    ip("link", "set", DEV, "down", check=False)
    ip("link", "del", DEV, check=False)

    if snap:
        gw = snap.get("default") or {}
        srv = snap.get("server_ip")
        if srv:
            ip("route", "del", f"{srv}/32", check=False)
        if gw.get("gateway") and gw.get("dev"):
            # only re-add if no default exists (after tun gone)
            if not default_route():
                ip("route", "add", "default", "via", gw["gateway"], "dev", gw["dev"], check=False)

    # only restart systemd-resolved if WE stopped it (don't start a service
    # the user had disabled/masked before `up`).
    if snap and snap.get("stopped_resolved"):
        r = subprocess.run(["systemctl", "start", "systemd-resolved"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            warn(f"could not restart systemd-resolved: {r.stderr.strip()}")

    _restore_resolv((snap or {}).get("resolv"))


def emergency() -> None:
    """Best-effort hard cleanup of processes, tun, routes and DNS after a crash."""
    from . import proc

    xr = proc.xray_running()
    t2 = proc.tun2socks_running()
    dev = dev_exists()
    snap = load_snapshot()
    bak = paths.RESOLV_BAK.exists()

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

    storage.clear(proc.XRAY_PID)
    storage.clear(proc.TUN2SOCKS_PID)
    storage.clear(paths.ACTIVE)
    storage.clear(paths.BACKUP)
    storage.clear(paths.RESOLV_BAK)
    info("done")
