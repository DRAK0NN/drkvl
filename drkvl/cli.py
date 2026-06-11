import argparse
import os
import sys
import time
from datetime import datetime

from . import clash, config, geo, link, profile, proc, stats, tun
from .util import fmt_bytes, fmt_duration, info, warn, err, resolve_host, port_open


def _require_root() -> bool:
    if os.geteuid() != 0:
        err("run with sudo")
        return False
    return True


def cmd_add(a) -> int:
    try:
        v = link.parse(a.uri)
    except ValueError as e:
        err(str(e))
        return 1
    name = profile.save(v, a.name)
    info(f"saved profile '{name}' ({v.host}:{v.port}, {v.network}/{v.security})")
    return 0


def cmd_list(a) -> int:
    items = profile.list_all()
    if not items:
        info("no profiles")
        return 0
    default = profile.DEFAULT.read_text().strip() if profile.DEFAULT.exists() else None
    for i, (n, v) in enumerate(items):
        mark = "*" if n == default else " "
        tag = v.name if v.name else ""
        sec = v.security or "none"
        print(f"{mark} {i}  {n:<24} {v.host}:{v.port}  {v.network}/{sec}  {tag}")
    return 0


def cmd_rm(a) -> int:
    try:
        n = profile.remove(a.target)
    except (FileNotFoundError, IndexError) as e:
        err(str(e))
        return 1
    info(f"removed '{n}'")
    return 0


def cmd_default(a) -> int:
    try:
        profile.set_default(a.target)
    except (FileNotFoundError, IndexError) as e:
        err(str(e))
        return 1
    info(f"default set to '{a.target}'")
    return 0


def _save_active(name: str, v: link.Vless, stopped_clash: list[str]) -> None:
    profile.write_json(profile.ACTIVE, {
        "name": name,
        "host": v.host,
        "port": v.port,
        "started": time.time(),
        "stopped_clash": stopped_clash,
    })


def cmd_up(a) -> int:
    if not _require_root():
        return 1

    try:
        name, v = profile.load(a.name)
    except (FileNotFoundError, IndexError) as e:
        err(str(e))
        return 1

    if proc.xray_running() or proc.tun2socks_running():
        err("already up. run 'drkvl down' or 'drkvl emergency-off' first")
        return 1

    if port_open(config.SOCKS_PORT):
        err(f"port {config.SOCKS_PORT} already in use (lsof -i :{config.SOCKS_PORT})")
        return 1

    info(f"loading profile '{name}'")
    try:
        server_ip = resolve_host(v.host)
    except RuntimeError as e:
        err(str(e))
        return 1

    gw = tun.default_route() or {}
    gw_dev = gw.get("dev")
    if not gw_dev:
        err("no default route on this host")
        return 1

    bypass = not a.no_bypass
    asset_dir = None
    if bypass:
        try:
            asset_dir = geo.ensure()
        except RuntimeError as e:
            err(str(e))
            warn("hint: drop bypass with `drkvl up --no-bypass`, or place "
                 "geosite.dat/geoip.dat in ~/.config/drkvl/assets/")
            return 1
        info(f"bypass on (geo assets: {asset_dir})")
    else:
        info("bypass disabled — all traffic via vpn")

    info(f"generating xray config (direct fwmark {hex(tun.DIRECT_FWMARK)} -> table {tun.DIRECT_TABLE})")
    cfg = config.build(v, bypass=bypass, direct_mark=tun.DIRECT_FWMARK, mark=tun.DIRECT_FWMARK)
    profile.ensure_dirs()
    config.dump(cfg, profile.XRAY_CONFIG)
    profile.chown_user(profile.XRAY_CONFIG)

    info(f"starting xray on socks5://127.0.0.1:{config.SOCKS_PORT}")
    try:
        proc.start_xray(profile.XRAY_CONFIG, asset_dir=asset_dir)
    except RuntimeError as e:
        err(str(e))
        return 1

    stopped_clash = clash.stop_active()

    try:
        tun.apply_up(server_ip, config.SOCKS_PORT)
    except (RuntimeError, OSError) as e:
        err(f"up failed: {e}")
        warn("rolling back")
        proc.stop_xray()
        try:
            tun.apply_down(tun.load_snapshot())
        except Exception:
            pass
        clash.start(stopped_clash)
        return 1

    _save_active(name, v, stopped_clash)
    info(f"up: {name} ({v.host}:{v.port})")
    return 0


def cmd_down(a) -> int:
    if not (proc.xray_running() or proc.tun2socks_running() or tun.dev_exists()):
        info("not running")
        return 0

    if not _require_root():
        return 1

    active = profile.read_json(profile.ACTIVE) or {}
    stopped_clash = active.get("stopped_clash") or []

    info("stopping xray")
    proc.stop_xray()

    info("tearing down tun and restoring routes")
    snap = tun.load_snapshot()
    try:
        tun.apply_down(snap)
    except Exception as e:
        err(f"teardown failed: {e}")
        return 1

    clash.start(stopped_clash)

    profile.clear(proc.TUN2SOCKS_PID)
    profile.clear(profile.ACTIVE)
    profile.clear(profile.BACKUP)
    profile.clear(profile.RESOLV_BAK)
    info("down")
    return 0


def cmd_emergency(a) -> int:
    xr = proc.xray_running()
    t2 = proc.tun2socks_running()
    dev = tun.dev_exists()
    snap = tun.load_snapshot()
    bak = profile.RESOLV_BAK.exists()
    active = profile.read_json(profile.ACTIVE) or {}
    stopped_clash = active.get("stopped_clash") or []

    if not (xr or t2 or dev or snap or bak or stopped_clash):
        info("nothing to clean up")
        return 0

    if not _require_root():
        return 1

    tun.emergency()
    clash.start(stopped_clash)
    return 0


def cmd_status(a) -> int:
    active = profile.read_json(profile.ACTIVE)
    xr = proc.xray_running()
    t2 = proc.tun2socks_running()
    state = "on" if (xr and t2) else ("partial" if (xr or t2) else "off")
    print(f"state:     {state}")
    print(f"xray:      {'running' if xr else 'stopped'}")
    print(f"tun2socks: {'running' if t2 else 'stopped'}")
    if active:
        up = time.time() - active.get("started", time.time())
        print(f"profile:   {active.get('name')}")
        print(f"server:    {active.get('host')}:{active.get('port')}")
        print(f"uptime:    {fmt_duration(up)}")
        print(f"started:   {datetime.fromtimestamp(active['started']).isoformat(timespec='seconds')}")
    return 0


def cmd_stats(a) -> int:
    if not proc.xray_running():
        err("xray not running")
        return 1

    def once(prev=None):
        up, dn = stats.proxy_traffic()
        line = f"↑ {fmt_bytes(up):>8}    ↓ {fmt_bytes(dn):>8}"
        if prev:
            du = up - prev[0]
            dd = dn - prev[1]
            line += f"    ({fmt_bytes(du)}/s up, {fmt_bytes(dd)}/s down)"
        return up, dn, line

    if not a.follow:
        _, _, line = once()
        print(line)
        return 0

    prev = None
    try:
        while True:
            cur = once(prev)
            sys.stdout.write("\r\033[K" + cur[2])
            sys.stdout.flush()
            prev = cur[:2]
            time.sleep(2)
    except KeyboardInterrupt:
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="drkvl", description="vless vpn client")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="add profile from vless:// link")
    a.add_argument("uri")
    a.add_argument("-n", "--name", help="profile name")
    a.set_defaults(fn=cmd_add)

    a = sub.add_parser("list", help="list profiles")
    a.set_defaults(fn=cmd_list)
    sub.add_parser("ls", help="alias for list").set_defaults(fn=cmd_list)

    a = sub.add_parser("rm", help="remove profile")
    a.add_argument("target", help="name or index")
    a.set_defaults(fn=cmd_rm)

    a = sub.add_parser("default", help="set default profile")
    a.add_argument("target", help="name or index")
    a.set_defaults(fn=cmd_default)

    a = sub.add_parser("up", help="connect")
    a.add_argument("name", nargs="?", help="profile name or index")
    a.add_argument("--no-bypass", action="store_true",
                   help="route all traffic via vpn (default: bypass ru sites)")
    a.set_defaults(fn=cmd_up)

    a = sub.add_parser("down", help="disconnect")
    a.set_defaults(fn=cmd_down)

    a = sub.add_parser("emergency-off", help="hard stop and clean tun/routes")
    a.set_defaults(fn=cmd_emergency)

    a = sub.add_parser("status", help="show status")
    a.set_defaults(fn=cmd_status)

    a = sub.add_parser("stats", help="show session traffic")
    a.add_argument("-f", "--follow", action="store_true")
    a.set_defaults(fn=cmd_stats)

    return p


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv == ["-i"]:
        if sys.stdout.isatty():
            from .tui import run
            return run()
        build_parser().print_help()
        return 0

    p = build_parser()
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print()
        return 130
