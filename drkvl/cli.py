import argparse
import ipaddress
import os
import sys
import time

from . import (bypass, clash, config, display, geo, link, ownership, paths,
               proc, speed, state, stats, storage, sub, tun)
from .util import fmt_bytes, have, info, warn, err, resolve_host, port_open


def _require_root() -> bool:
    if os.geteuid() != 0:
        err("run with sudo")
        return False
    return True


def _await_socks(port: int, attempts: int = 30, delay: float = 0.1) -> bool:
    # proc._start only polls once after 0.15s; confirm xray actually bound the
    # socks port (and is still alive) before we hand traffic to the tunnel,
    # else we'd report a false 'up' while everything blackholes.
    for _ in range(attempts):
        if port_open(port):
            return True
        if not proc.xray_running():
            return False
        time.sleep(delay)
    return False


def _profile_block_reason(v) -> "str | None":
    """Why a profile cannot be connected on this host, or None (fail-closed).

    Only hysteria profiles can be blocked: they need xray >= HYSTERIA_MIN, and
    ``insecure=1`` without a cert pin can't work because xray removed
    allowInsecure — the TLS handshake would just fail. Refusing up front beats a
    silent dead tunnel.
    """
    if getattr(v, "kind", "") != "hy2":
        return None
    ver = proc.xray_version()
    if ver and ver[:2] < proc.HYSTERIA_MIN:
        lo = ".".join(map(str, proc.HYSTERIA_MIN))
        return (f"hysteria outbound needs xray >= {lo}, but this xray is "
                f"{ver[0]}.{ver[1]}.{ver[2]} — upgrade xray")
    if v.insecure and not v.pin_sha256:
        return ("insecure=1 without pinSHA256: this xray removed allowInsecure, "
                "so TLS verification can't be skipped and the handshake would fail")
    return None


def _count_insecure_hy2(profiles) -> int:
    """Count hysteria profiles with insecure=1 but no cert pin (unusable on connect)."""
    return sum(1 for p in profiles
               if getattr(p, "kind", "") == "hy2" and p.insecure and not p.pin_sha256)


def _partition_testable(profiles):
    """Split ``(name, v)`` profiles into (testable, blocked_error_rows).

    Blocked profiles are turned into error :class:`speed.Result` rows (and a
    warning) so they still show in the speed table instead of wasting a full
    connect attempt that is guaranteed to fail.
    """
    testable, blocked = [], []
    for name, v in profiles:
        reason = _profile_block_reason(v)
        if reason:
            warn(f"skipping '{name}': {reason}")
            blocked.append(speed.Result(name, v.host, v.port, None, "error"))
        else:
            testable.append((name, v))
    return testable, blocked


def cmd_add(a) -> int:
    """Parse a vless:// or hysteria2:// URI and save it as a profile."""
    try:
        v = link.parse_any(a.uri)
    except ValueError as e:
        err(str(e))
        return 1
    if getattr(v, "kind", "") == "hy2":
        if v.obfs and v.obfs != "salamander":
            warn(f"unknown obfs '{v.obfs}'; only salamander is supported — ignoring it")
        if 0 < v.hop_interval < config.HY_HOP_INTERVAL_MIN:
            warn(f"hopInterval {v.hop_interval}s is below xray's {config.HY_HOP_INTERVAL_MIN}s "
                 f"minimum — ignored; xray will use its 30s default")
    name = storage.save(v, a.name)
    info(f"saved profile '{name}' ({v.host}:{v.port}, {v.network}/{v.security})")
    return 0


def cmd_list(a) -> int:
    """Print all saved profiles."""
    lines = display.list_lines()
    if not lines:
        info("no profiles")
        return 0
    for line in lines:
        print(line)
    return 0


def cmd_rm(a) -> int:
    """Remove the profile named or indexed by ``a.target``."""
    try:
        n = storage.remove(a.target)
    except (FileNotFoundError, IndexError) as e:
        err(str(e))
        return 1
    info(f"removed '{n}'")
    return 0


def cmd_default(a) -> int:
    """Set the default profile to ``a.target``."""
    try:
        state.set_default(a.target)
    except (FileNotFoundError, IndexError) as e:
        err(str(e))
        return 1
    info(f"default set to '{a.target}'")
    return 0


def cmd_sub(a) -> int:
    """Download a subscription, add its vless profiles, and remember the URL."""
    try:
        body = sub.fetch(a.url)
    except RuntimeError as e:
        err(str(e))
        return 1
    profiles, skipped = sub.parse_links(body)
    if not profiles:
        err("no supported links found in subscription (vless/hysteria2)")
        if skipped:
            warn(f"{skipped} unsupported link(s) skipped")
        return 1
    sub.remove_names(sub.url_profiles(a.url))   # re-subscribing replaces the old set
    names = sub.add_profiles(profiles)
    sub.set_url_profiles(a.url, names)
    msg = f"added {len(names)} profile(s) from subscription"
    if skipped:
        msg += f" ({skipped} unsupported skipped)"
    info(msg)
    n_ins = _count_insecure_hy2(profiles)
    if n_ins:
        warn(f"{n_ins} hysteria profile(s) set insecure=1 without pinSHA256 — they'll be "
             f"refused on connect (this xray removed allowInsecure); add pinSHA256 to use them")
    return 0


def cmd_sub_update(a) -> int:
    """Refresh subscriptions (all saved, or just ``a.url``), replacing each one's profiles.

    Each subscription is fetched BEFORE its old profiles are removed, and only
    that subscription's own profiles are touched, so a network blip on one never
    deletes another's servers or corrupts the url->profiles map.
    """
    if a.url:
        urls = [a.url]
    else:
        urls = sub.saved_urls()
        if not urls:
            err("no saved subscriptions; run 'drkvl sub <url>' first")
            return 1

    total = 0
    insecure_total = 0
    for url in urls:
        try:
            body = sub.fetch(url)
        except RuntimeError as e:
            err(f"{url}: {e} (keeping existing profiles)")
            continue
        profiles, skipped = sub.parse_links(body)
        if not profiles:
            err(f"{url}: no supported links found (keeping existing profiles)")
            continue
        sub.remove_names(sub.url_profiles(url))   # only after a good fetch
        names = sub.add_profiles(profiles)
        sub.set_url_profiles(url, names)
        total += len(names)
        insecure_total += _count_insecure_hy2(profiles)
        line = f"{url}: {len(names)} profile(s)"
        if skipped:
            line += f" ({skipped} skipped)"
        info(line)
    info(f"updated {total} profile(s) from {len(urls)} subscription(s)")
    if insecure_total:
        warn(f"{insecure_total} hysteria profile(s) set insecure=1 without pinSHA256 — they'll "
             f"be refused on connect (this xray removed allowInsecure); add pinSHA256 to use them")
    return 0


def _save_active(name: str, v: link.Profile, stopped_clash: list[str]) -> None:
    state.write_active({
        "name": name,
        "host": v.host,
        "port": v.port,
        "transport": f"{v.network}/{v.security}",
        "started": time.time(),
        "stopped_clash": stopped_clash,
    })


def _attempt(name: str, v: link.Profile, bypass: bool, asset_dir, socks_wait: int):
    """Start xray for one profile and wait for its socks port to open.

    Returns the resolved server IP on success, or None after warning and
    stopping xray on failure (so the next fallback candidate can be tried).
    """
    try:
        server_ip = resolve_host(v.host)
    except RuntimeError as e:
        warn(f"{name}: {e}")
        return None
    cfg = config.build(v, bypass=bypass, direct_mark=tun.DIRECT_FWMARK,
                       mark=tun.DIRECT_FWMARK, server_ip=server_ip)
    ownership.ensure_dirs()
    config.dump(cfg, paths.XRAY_CONFIG)
    ownership.chown_user(paths.XRAY_CONFIG)
    try:
        proc.start_xray(paths.XRAY_CONFIG, asset_dir=asset_dir)
    except RuntimeError as e:
        warn(f"{name}: xray failed to start ({e})")
        return None
    if not _await_socks(config.SOCKS_PORT, attempts=socks_wait, delay=0.1):
        warn(f"{name}: socks port {config.SOCKS_PORT} did not open within "
             f"{socks_wait // 10}s (see {proc.XRAY_LOG})")
        proc.stop_xray()
        return None
    return server_ip


def _select_working(candidates, attempt):
    """Try each ``(name, vless)`` via ``attempt`` in order.

    Return the first ``(name, vless, server_ip)`` whose attempt succeeds, or
    None if none connect. Stops on the first success.
    """
    for name, v in candidates:
        info(f"trying '{name}' ({v.host}:{v.port})")
        server_ip = attempt(name, v)
        if server_ip:
            return name, v, server_ip
    return None


def cmd_up(a) -> int:
    """Connect: start xray, bring up the tun, and route all traffic through the VPN.

    With ``--fallback`` it speed-tests every saved profile in parallel and
    connects to the fastest one that responded.
    """
    if not _require_root():
        return 1

    if proc.xray_running() or proc.tun2socks_running():
        err("already up. run 'drkvl down' or 'drkvl emergency-off' first")
        return 1

    if port_open(config.SOCKS_PORT):
        err(f"port {config.SOCKS_PORT} already in use (lsof -i :{config.SOCKS_PORT})")
        return 1

    if a.fallback:
        profiles = storage.list_all()
        if not profiles:
            err("no profiles to try")
            return 1
        if not have("xray"):
            err("xray not found in PATH")
            return 1
        testable, blocked = _partition_testable(profiles)
        info(f"speed-testing {len(testable)} profile(s) in parallel...")
        results = speed.sort_results(speed.run_tests(testable) + blocked)
        for line in display.speed_table(results, color=sys.stdout.isatty()):
            print(line)
        responded = [r for r in results if r.status == "ok"]
        if not responded:
            err("no profile responded")
            return 1
        best = responded[0]
        info(f"fastest: {best.name} ({best.latency_ms:.0f}ms) — connecting "
             f"(falling back through {len(responded)} responder(s) if needed)")
        # keep them in latency order so a connect failure falls back to the next
        candidates = []
        for r in responded:
            try:
                candidates.append(storage.load(r.name))
            except (FileNotFoundError, IndexError):
                pass
        if not candidates:
            err("no profile responded")
            return 1
    else:
        try:
            candidates = [storage.load(a.name)]
        except (FileNotFoundError, IndexError) as e:
            err(str(e))
            return 1
    # fail-closed: refuse (single) or drop (fallback) profiles that can't connect
    # here (old xray for hysteria, or hy2 insecure=1 without a pin).
    usable = []
    for name, v in candidates:
        reason = _profile_block_reason(v)
        if reason is None:
            usable.append((name, v))
        elif a.fallback:
            warn(f"skipping '{name}': {reason}")
        else:
            err(f"cannot connect '{name}': {reason}")
            return 1
    if not usable:
        err("no usable profile")
        return 1
    candidates = usable

    socks_wait = 30    # 3s for the real connect (winner already proven reachable)

    gw = tun.default_route() or {}
    if not gw.get("dev"):
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

    chosen = _select_working(
        candidates,
        lambda name, v: _attempt(name, v, bypass, asset_dir, socks_wait))
    if not chosen:
        err("no profile connected")
        return 1
    name, v, server_ip = chosen

    stopped_clash = clash.stop_active()

    try:
        tun.apply_up(server_ip, config.SOCKS_PORT)
    except (RuntimeError, OSError) as e:
        err(f"up failed: {e}")
        warn("rolling back")
        proc.stop_xray()
        try:
            tun.apply_down(tun.load_snapshot())
        except Exception as re:
            err(f"rollback failed: {re}")
            err("routing may be inconsistent — run 'sudo drkvl emergency-off'")
        clash.start(stopped_clash)
        for f in (proc.TUN2SOCKS_PID, paths.ACTIVE, paths.BACKUP,
                  paths.RESOLV_BAK):
            storage.clear(f)
        return 1

    _save_active(name, v, stopped_clash)
    info(f"up: {name} ({v.host}:{v.port})")
    # connection is already established; this socks-side IP check is bounded by
    # curl --max-time so it can't hang or delay anything.
    print(display.vpn_ip_line(config.SOCKS_PORT, color=sys.stdout.isatty()))
    return 0


def cmd_down(a) -> int:
    """Tear down the tunnel and restore the prior routing/DNS state."""
    if not (proc.xray_running() or proc.tun2socks_running() or tun.dev_exists()):
        info("not running")
        return 0

    if not _require_root():
        return 1

    active = state.read_active() or {}
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

    storage.clear(proc.TUN2SOCKS_PID)
    storage.clear(paths.ACTIVE)
    storage.clear(paths.BACKUP)
    storage.clear(paths.RESOLV_BAK)
    info("down")
    return 0


def cmd_emergency(a) -> int:
    """Hard-stop everything and clean up tun/routes/DNS, even after a crash."""
    xr = proc.xray_running()
    t2 = proc.tun2socks_running()
    dev = tun.dev_exists()
    snap = tun.load_snapshot()
    bak = paths.RESOLV_BAK.exists()
    active = state.read_active() or {}
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
    """Print connection state and the active session, if any."""
    for line in display.status_lines():
        print(line)
    return 0


def cmd_stats(a) -> int:
    """Print proxy traffic counters, optionally refreshing with ``--follow``."""
    if not proc.xray_running():
        err("xray not running")
        return 1

    def once(prev=None):
        """Sample traffic once, returning ``(up, dn, line)`` with optional rate."""
        up, dn = stats.proxy_traffic()
        line = display.stats_line(up, dn)
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


def cmd_bypass_import(a) -> int:
    """Import an Amnezia bypass JSON file into the custom direct-routing lists."""
    try:
        st = bypass.import_file(a.file)
    except RuntimeError as e:
        err(str(e))
        return 1
    print(display.bypass_import_line(st, color=sys.stdout.isatty()))
    return 0


def cmd_bypass_list(a) -> int:
    """Show how many custom bypass domains/IPs are currently active."""
    nd, ni = bypass.stats()
    for line in display.bypass_status_lines(nd, ni, color=sys.stdout.isatty()):
        print(line)
    return 0


def cmd_bypass_clear(a) -> int:
    """Remove the custom bypass lists."""
    bypass.clear()
    info("custom bypass lists removed")
    return 0


def cmd_ru_dns(a) -> int:
    """Show or set the resolver used for RU-domain lookups (resolved direct).

    RU domains are resolved via this IP over the physical link (not the tunnel)
    so they get in-country CDN answers — at the cost of that resolver seeing
    your RU queries. Default is Yandex (config.DNS_RU).
    """
    if not a.ip:
        cur = config.ru_dns()
        tag = " (default)" if cur == config.DNS_RU else ""
        info(f"ru-dns: {cur}{tag}")
        return 0
    if a.ip == "default":
        storage.clear(paths.RU_DNS)
        info(f"ru-dns reset to default ({config.DNS_RU})")
        return 0
    try:
        if ipaddress.ip_address(a.ip).version != 4:
            raise ValueError
    except ValueError:
        err(f"not a valid IPv4 address: {a.ip} (IPv6 egress is blocked while up)")
        return 1
    storage.write_text(paths.RU_DNS, a.ip + "\n")
    info(f"ru-dns set to {a.ip}")
    return 0


def _full_test_one(name: str, v: link.Profile, bypass: bool, asset_dir) -> "speed.Result":
    """Bring the real TUN stack up for one profile, curl THROUGH the tun, tear down.

    Mirrors a real `up` (xray with fwmark -> tun2socks -> route swap) so the
    latency is authoritative; always restores the network in a finally.
    """
    try:
        server_ip = resolve_host(v.host)
    except RuntimeError as e:
        warn(f"{name}: {e}")
        return speed.Result(name, v.host, v.port, None, "error")
    cfg = config.build(v, bypass=bypass, direct_mark=tun.DIRECT_FWMARK,
                       mark=tun.DIRECT_FWMARK, server_ip=server_ip)
    ownership.ensure_dirs()
    config.dump(cfg, paths.XRAY_CONFIG)
    ownership.chown_user(paths.XRAY_CONFIG)
    try:
        proc.start_xray(paths.XRAY_CONFIG, asset_dir=asset_dir)
    except RuntimeError as e:
        warn(f"{name}: xray failed to start ({e})")
        return speed.Result(name, v.host, v.port, None, "error")
    if not _await_socks(config.SOCKS_PORT, attempts=100, delay=0.1):   # 10s
        warn(f"{name}: socks port {config.SOCKS_PORT} did not open")
        proc.stop_xray()
        return speed.Result(name, v.host, v.port, None, "error")
    try:
        tun.apply_up(server_ip, config.SOCKS_PORT)
    except (RuntimeError, OSError) as e:
        warn(f"{name}: routing setup failed ({e})")
        proc.stop_xray()
        try:
            tun.apply_down(tun.load_snapshot())
        except Exception:
            pass
        return speed.Result(name, v.host, v.port, None, "error")
    try:
        status, latency = speed.curl_direct(timeout=10)
    finally:
        proc.stop_xray()
        try:
            tun.apply_down(tun.load_snapshot())
        except Exception as e:
            warn(f"{name}: teardown warning: {e}")
    return speed.Result(name, v.host, v.port, latency, status)


def _speedtest_full(profiles) -> int:
    """Serial, authoritative speed test through the real TUN stack (needs root)."""
    if not _require_root():
        return 1
    if proc.xray_running() or proc.tun2socks_running() or tun.dev_exists():
        err("already up — run 'drkvl down' first")
        return 1
    if port_open(config.SOCKS_PORT):
        err(f"port {config.SOCKS_PORT} already in use")
        return 1
    if not have("tun2socks"):
        err("tun2socks not found in PATH")
        return 1
    gw = tun.default_route() or {}
    if not gw.get("dev"):
        err("no default route on this host")
        return 1
    try:
        asset_dir = geo.ensure()
    except RuntimeError as e:
        err(str(e))
        warn("hint: place geosite.dat/geoip.dat in ~/.config/drkvl/assets/")
        return 1

    testable, blocked = _partition_testable(profiles)
    warn(f"full test: connecting each of {len(testable)} profile(s) through the TUN, "
         f"one at a time — slow, and briefly disrupts your network")
    stopped_clash = clash.stop_active()
    results = list(blocked)
    try:
        for name, v in testable:
            info(f"testing '{name}' ({v.host}:{v.port})...")
            results.append(_full_test_one(name, v, True, asset_dir))
    finally:
        clash.start(stopped_clash)
        for f in (proc.TUN2SOCKS_PID, paths.BACKUP, paths.RESOLV_BAK):
            storage.clear(f)

    for line in display.speed_table(speed.sort_results(results), color=sys.stdout.isatty()):
        print(line)
    return 0


def cmd_speedtest(a) -> int:
    """Speed-test all profiles and print a latency table.

    Default: fast parallel socks-only test (no root, no connection). ``--full``
    connects each profile through the real TUN stack one at a time (needs root)
    — slow but authoritative.
    """
    profiles = storage.list_all()
    if not profiles:
        err("no profiles")
        return 1
    if not have("xray"):
        err("xray not found in PATH")
        return 1
    if getattr(a, "full", False):
        return _speedtest_full(profiles)
    testable, blocked = _partition_testable(profiles)
    info(f"speed-testing {len(testable)} profile(s)...")
    results = speed.sort_results(speed.run_tests(testable) + blocked)
    for line in display.speed_table(results, color=sys.stdout.isatty()):
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser for all drkvl subcommands."""
    p = argparse.ArgumentParser(prog="drkvl", description="vless vpn client")
    sp = p.add_subparsers(dest="cmd", required=True)

    a = sp.add_parser("add", help="add profile from vless:// or hysteria2:// link")
    a.add_argument("uri")
    a.add_argument("-n", "--name", help="profile name")
    a.set_defaults(fn=cmd_add)

    a = sp.add_parser("sub", help="add a subscription (base64 list of vless links)")
    a.add_argument("url")
    a.set_defaults(fn=cmd_sub)

    a = sp.add_parser("sub-update", help="refresh saved subscriptions")
    a.add_argument("url", nargs="?", help="only update this subscription")
    a.set_defaults(fn=cmd_sub_update)

    a = sp.add_parser("list", help="list profiles")
    a.set_defaults(fn=cmd_list)
    sp.add_parser("ls", help="alias for list").set_defaults(fn=cmd_list)

    a = sp.add_parser("rm", help="remove profile")
    a.add_argument("target", help="name or index")
    a.set_defaults(fn=cmd_rm)

    a = sp.add_parser("default", help="set default profile")
    a.add_argument("target", help="name or index")
    a.set_defaults(fn=cmd_default)

    a = sp.add_parser("up", help="connect")
    a.add_argument("name", nargs="?", help="profile name or index")
    a.add_argument("--no-bypass", action="store_true",
                   help="route all traffic via vpn (default: bypass ru sites)")
    a.add_argument("--fallback", action="store_true",
                   help="speed-test all profiles in parallel and connect to the fastest")
    a.set_defaults(fn=cmd_up)

    a = sp.add_parser("down", help="disconnect")
    a.set_defaults(fn=cmd_down)

    a = sp.add_parser("emergency-off", help="hard stop and clean tun/routes")
    a.set_defaults(fn=cmd_emergency)

    a = sp.add_parser("status", help="show status")
    a.set_defaults(fn=cmd_status)

    a = sp.add_parser("stats", help="show session traffic")
    a.add_argument("-f", "--follow", action="store_true")
    a.set_defaults(fn=cmd_stats)

    a = sp.add_parser("speedtest", help="parallel latency test of all profiles")
    a.add_argument("--full", action="store_true",
                   help="authoritative test through the real TUN stack (needs root, slow)")
    a.set_defaults(fn=cmd_speedtest)

    a = sp.add_parser("bypass-import", help="import custom bypass list (Amnezia JSON)")
    a.add_argument("file", help="path to the Amnezia JSON file")
    a.set_defaults(fn=cmd_bypass_import)

    a = sp.add_parser("bypass-list", help="show custom bypass stats")
    a.set_defaults(fn=cmd_bypass_list)

    a = sp.add_parser("bypass-clear", help="remove custom bypass lists")
    a.set_defaults(fn=cmd_bypass_clear)

    a = sp.add_parser("ru-dns", help="show/set the RU-domain resolver IP")
    a.add_argument("ip", nargs="?",
                   help="IPv4 to use, or 'default' to reset; omit to show current")
    a.set_defaults(fn=cmd_ru_dns)

    return p


def main(argv: "list[str] | None" = None) -> int:
    """CLI entry point: dispatch ``argv`` to a command, or launch the TUI."""
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
