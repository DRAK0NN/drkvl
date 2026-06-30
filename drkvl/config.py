import json
import os
from .link import Vless

SOCKS_PORT = 1080
API_PORT = 10085


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


def build(v: Vless, socks_port: int = SOCKS_PORT, api_port: int = API_PORT,
          mark: int = 0, bypass: bool = True, direct_mark: int = 0,
          geo: bool = True) -> dict:
    """Build the full xray config dict for ``v`` (socks inbound, routing, marks).

    ``geo=False`` drops all geoip/geosite routing rules so the config needs no
    .dat assets — used for throwaway speed-test xrays.
    """
    user = {"id": v.uuid, "encryption": v.encryption or "none"}
    if v.flow:
        user["flow"] = v.flow

    proxy_stream = _stream(v)
    sockopt: dict = {}
    if mark:
        # SO_MARK: paired with `ip rule fwmark <m> lookup main` so the
        # kernel ignores foreign policy routing (mihomo's table 2022 etc.).
        sockopt["mark"] = mark
    if sockopt:
        proxy_stream["sockopt"] = sockopt

    direct: dict = {"tag": "direct", "protocol": "freedom"}
    if direct_mark:
        # without this, direct-routed traffic (geosite:ru, geoip:ru) walks
        # back into drkvl0 (the new default) and loops through tun2socks ->
        # xray -> drkvl0 forever. mark sockets so a dedicated ip rule sends
        # them to a side table whose default is the physical gw.
        direct["streamSettings"] = {"sockopt": {"mark": direct_mark}}

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": ["tcp://1.1.1.1", "tcp://8.8.8.8"],
            "queryStrategy": "UseIPv4",
        },
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
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": v.host,
                        "port": v.port,
                        "users": [user],
                    }]
                },
                "streamSettings": proxy_stream,
            },
            direct,
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "dns-out", "protocol": "dns"},
        ],
        "routing": _routing(bypass, geo),
    }


def _routing(bypass: bool, geo: bool = True) -> dict:
    rules: list[dict] = [
        {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"},
        {"type": "field", "inboundTag": ["socks-in"], "port": "53", "outboundTag": "dns-out"},
        {"type": "field", "port": "5355", "outboundTag": "block"},
        {"type": "field", "ip": ["fe80::/10"], "outboundTag": "block"},
    ]
    if geo:
        # routing private/LAN traffic direct needs geoip.dat at parse time
        rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    if bypass:
        rules += [
            {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
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
