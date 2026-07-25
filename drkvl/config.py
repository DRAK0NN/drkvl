import ipaddress
import json
import os
from . import paths
from .link import Vless, Profile

SOCKS_PORT = 1080
API_PORT = 10085

# Default RU-domain resolver (Yandex), queried DIRECT (marked -> physical iface)
# so RU sites get their in-country CDN answers. Must be a DISTINCT IP from the
# tunnelled resolvers so routing can send only its queries to `direct`. This is
# a deliberate anti-censorship choice (RU lookups leave via a Russian resolver);
# override it with `drkvl ru-dns <ip>`. See :func:`ru_dns`.
DNS_RU = "77.88.8.8"


def ru_dns() -> str:
    """Return the configured RU-domain resolver IP, or :data:`DNS_RU`.

    Reads a single IPv4 literal from ``paths.RU_DNS`` (written by
    ``drkvl ru-dns``); anything missing or non-IPv4 falls back to the default.
    IPv4 only, because IPv6 egress is blocked while the tunnel is up.
    """
    try:
        raw = paths.RU_DNS.read_text().strip()
    except OSError:
        return DNS_RU
    try:
        if ipaddress.ip_address(raw).version == 4:
            return raw
    except ValueError:
        pass
    return DNS_RU


def _stream(v: Vless) -> dict:
    net = v.network
    if net in ("xhttp", "splithttp"):
        net = "xhttp"

    st: dict = {"network": net}

    if net == "xhttp":
        xs: dict = {}
        if v.extra:
            try:
                xs = json.loads(v.extra)
            except json.JSONDecodeError:
                xs = {}
        if v.path:
            xs["path"] = v.path
        if v.mode:
            xs["mode"] = v.mode
        if v.h_host:
            xs["host"] = v.h_host
        # xray defaults to xmux.maxConcurrency=1, which means every new
        # socks-in connection triggers a fresh tcp + reality handshake.
        # in tun mode every app socket goes through socks-in, so dozens
        # of background flows (browsers, telegram, etc.) pile up hundreds
        # of half-open xmux clients and starve the server. lift it so a
        # single tcp can multiplex many streams.
        xs.setdefault("xmux", {
            "maxConcurrency": "16-32",
            "maxConnections": 0,
            "cMaxReuseTimes": "64-128",
            "hMaxRequestTimes": "800-900",
            "hMaxReusableSecs": "1800-3000",
        })
        st["xhttpSettings"] = xs

    elif net == "ws":
        ws: dict = {"path": v.path or "/"}
        if v.h_host:
            ws["host"] = v.h_host
            ws["headers"] = {"Host": v.h_host}
        st["wsSettings"] = ws

    elif net == "httpupgrade":
        hu: dict = {"path": v.path or "/"}
        if v.h_host:
            hu["host"] = v.h_host
        st["httpupgradeSettings"] = hu

    elif net == "grpc":
        gs: dict = {}
        if v.service_name:
            gs["serviceName"] = v.service_name
        if v.authority:
            gs["authority"] = v.authority
        if v.mode in ("multi", "gun"):
            gs["multiMode"] = v.mode == "multi"
        st["grpcSettings"] = gs

    elif net == "tcp":
        st["tcpSettings"] = {}

    if v.security == "reality":
        rs: dict = {
            "serverName": v.sni or v.host,
            "publicKey": v.pbk,
            "fingerprint": v.fp or "chrome",
            "shortId": v.sid,
        }
        if v.spx:
            rs["spiderX"] = v.spx
        if v.pqv:
            # ML-DSA-65 client verify key (xray ≥1.8.x)
            rs["mldsa65Verify"] = v.pqv
        st["security"] = "reality"
        st["realitySettings"] = rs

    elif v.security == "tls":
        ts: dict = {"serverName": v.sni or v.h_host or v.host}
        if v.fp:
            ts["fingerprint"] = v.fp
        if v.alpn:
            ts["alpn"] = v.alpn.split(",")
        st["security"] = "tls"
        st["tlsSettings"] = ts

    else:
        st["security"] = "none"

    return st


def _proxy_outbound(v: Profile, mark: int) -> dict:
    """Build the ``proxy`` outbound for ``v`` (vless or hysteria)."""
    if getattr(v, "kind", "vless") == "hy2":
        return _hysteria_outbound(v, mark)

    user = {"id": v.uuid, "encryption": v.encryption or "none"}
    if v.flow:
        user["flow"] = v.flow
    proxy_stream = _stream(v)
    if mark:
        # SO_MARK: paired with `ip rule fwmark <m> lookup main` so the
        # kernel ignores foreign policy routing (mihomo's table 2022 etc.).
        proxy_stream["sockopt"] = {"mark": mark}
    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": v.host, "port": v.port, "users": [user],
        }]},
        "streamSettings": proxy_stream,
    }


# udphop interval floor (seconds). xray rejects a smaller value at config load:
# infra/conf validates `Interval < 5 -> error`, and the dialer builds it as
# `time.Duration(interval) * time.Second` (transport/internet/hysteria/dialer.go),
# so the unit is SECONDS, not milliseconds. Below the floor we omit it and let
# xray use its 30s default rather than fail the whole config.
HY_HOP_INTERVAL_MIN = 5


def _hysteria_outbound(v: Profile, mark: int) -> dict:
    """Build the ``proxy`` outbound as an xray-native hysteria2 outbound.

    Field placement is verified against XTLS/Xray-core v26.5.9 (infra/conf):
      - salamander obfs -> streamSettings.finalmask.udp[] (a []conf.Mask); the
        stream-level ``udpmasks`` key is silently ignored by xray.
      - port-hopping -> streamSettings.finalmask.quicParams.udpHop; the
        ``hysteriaSettings.udphop`` location is deprecated (Build only logs a
        warning and never applies it).
      - auth/version stay in hysteriaSettings.
    Congestion control is left at xray's default (server runs
    ``ignoreClientBandwidth``): quicParams carries ONLY udpHop, never
    congestion/brutal/bandwidth. ``insecure`` is NOT mapped to allowInsecure
    (removed from xray); verification can only be relaxed via a cert pin.
    """
    tls: dict = {"serverName": v.sni or v.host, "alpn": ["h3"]}
    if v.pin_sha256:
        tls["pinnedPeerCertSha256"] = v.pin_sha256

    stream: dict = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": v.auth},
    }

    finalmask: dict = {}
    if v.obfs == "salamander" and v.obfs_password:
        finalmask["udp"] = [
            {"type": "salamander", "settings": {"password": v.obfs_password}}]
    if v.ports:
        hop: dict = {"ports": v.ports}
        if v.hop_interval >= HY_HOP_INTERVAL_MIN:
            hop["interval"] = v.hop_interval
        finalmask["quicParams"] = {"udpHop": hop}
    if finalmask:
        stream["finalmask"] = finalmask

    if mark:
        stream["sockopt"] = {"mark": mark}
    return {
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {"version": 2, "address": v.host, "port": v.port},
        "streamSettings": stream,
    }


def build(v: Profile, socks_port: int = SOCKS_PORT, api_port: int = API_PORT,
          mark: int = 0, bypass: bool = True, direct_mark: int = 0,
          geo: bool = True) -> dict:
    """Build the full xray config dict for ``v`` (socks inbound, routing, marks).

    ``v`` may be a :class:`~drkvl.link.Vless` or :class:`~drkvl.link.Hy2`; only
    the ``proxy`` outbound differs, everything else (routing, dns, marks) is
    engine-agnostic. ``geo=False`` drops all geoip/geosite routing rules so the
    config needs no .dat assets — used for throwaway speed-test xrays.
    """
    proxy_ob = _proxy_outbound(v, mark)

    direct: dict = {"tag": "direct", "protocol": "freedom"}
    if direct_mark:
        # without this, direct-routed traffic (geosite:ru, geoip:ru) walks
        # back into drkvl0 (the new default) and loops through tun2socks ->
        # xray -> drkvl0 forever. mark sockets so a dedicated ip rule sends
        # them to a side table whose default is the physical gw.
        direct["streamSettings"] = {"sockopt": {"mark": direct_mark}}

    # dns-out only hijacks :53 into xray's built-in resolver; it carries NO mark.
    # The resolver's own upstream queries are split by routing (see _routing):
    # RU-domain lookups egress via `direct` (marked -> physical), everything else
    # via `proxy` (inside the tunnel) — so non-RU DNS no longer leaks to 1.1.1.1
    # in cleartext, and there is no dns-out -> drkvl0 loop (neither path uses the
    # drkvl0 default route, which was the only reason dns-out used to be marked).
    dns_out: dict = {"tag": "dns-out", "protocol": "dns"}

    tunnel = bool(direct_mark)      # a real `up` (tun present) vs a speedtest config

    return {
        "log": {"loglevel": "warning"},
        "dns": _dns(bypass, tunnel),
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "api-in",
                "port": api_port,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            proxy_ob,
            direct,
            {"tag": "block", "protocol": "blackhole"},
            dns_out,
        ],
        "routing": _routing(bypass, geo, tunnel),
    }


def _dns(bypass: bool, tunnel: bool) -> dict:
    """Build the xray built-in resolver.

    Without a tunnel (speedtest configs) this is the old, simple, fast local
    resolver. With a tunnel, the resolver's upstream queries are ``tag``-ged
    ``dns-in`` so :func:`_routing` can split them by outbound; with ``bypass``
    a RU server (``DNS_RU``, routed direct) resolves RU domains in-country while
    everything else uses 1.1.1.1/8.8.8.8 (routed through the proxy).
    ``skipFallback`` keeps non-RU domains OFF the RU server (else they would
    resolve direct and leak).
    """
    if not tunnel:
        return {"queryStrategy": "UseIPv4",
                "servers": ["tcp://1.1.1.1", "tcp://8.8.8.8"]}
    servers: list = []
    if bypass:
        from . import bypass as _bypass
        ru = ["geosite:category-ru"] + [f"domain:{d}" for d in _bypass.load_domains()]
        servers.append({"address": ru_dns(), "domains": ru, "skipFallback": True})
    servers += ["tcp://1.1.1.1", "tcp://8.8.8.8"]
    return {"tag": "dns-in", "queryStrategy": "UseIPv4", "servers": servers}


def _routing(bypass: bool, geo: bool = True, tunnel: bool = False) -> dict:
    rules: list[dict] = [
        {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"},
        {"type": "field", "inboundTag": ["socks-in"], "port": "53", "outboundTag": "dns-out"},
        {"type": "field", "port": "5355", "outboundTag": "block"},
        {"type": "field", "ip": ["fe80::/10"], "outboundTag": "block"},
    ]
    if tunnel:
        # split the resolver's OWN upstream queries (inboundTag dns-in): the RU
        # resolver (DNS_RU) egresses `direct` (marked -> physical), everything
        # else `proxy` (inside the tunnel). This closes the cleartext DNS leak
        # while keeping RU domains resolved in-country. Neither branch touches
        # the drkvl0 default route, so there is no dns-out -> tun loop.
        if bypass:
            rules.append({"type": "field", "inboundTag": ["dns-in"],
                          "ip": [ru_dns()], "outboundTag": "direct"})
        rules.append({"type": "field", "inboundTag": ["dns-in"], "outboundTag": "proxy"})
    if geo:
        # routing private/LAN traffic direct needs geoip.dat at parse time
        rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    if bypass:
        # merge any custom bypass lists imported via `drkvl bypass-import`
        from . import bypass as _bypass
        domains = ["geosite:category-ru"] + [f"domain:{d}" for d in _bypass.load_domains()]
        ips = ["geoip:ru"] + _bypass.load_ips()
        rules += [
            {"type": "field", "domain": domains, "outboundTag": "direct"},
            {"type": "field", "ip": ips, "outboundTag": "direct"},
        ]
    rules.append({"type": "field", "port": "0-65535", "outboundTag": "proxy"})
    return {
        # IPIfNonMatch: try domain rules first, then resolve and try ip rules.
        # needed so geosite:category-ru catches by host while geoip:ru catches
        # destinations the client already resolved.
        "domainStrategy": "IPIfNonMatch" if bypass else "AsIs",
        "rules": rules,
    }


def dump(cfg: dict, path: "os.PathLike | str") -> None:
    """Write ``cfg`` as JSON to ``path`` with mode 0600, refusing symlinks."""
    fd = os.open(str(path),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
