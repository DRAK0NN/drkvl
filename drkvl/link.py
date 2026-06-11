from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, unquote


@dataclass
class Vless:
    uuid: str
    host: str
    port: int
    name: str = ""

    network: str = "tcp"          # tcp, ws, grpc, xhttp, httpupgrade
    security: str = "none"        # reality, tls, none
    encryption: str = "none"
    flow: str = ""

    sni: str = ""
    fp: str = ""
    alpn: str = ""

    # reality
    pbk: str = ""
    sid: str = ""
    spx: str = ""
    pqv: str = ""                 # ML-DSA-65 verify key

    # transport-specific
    path: str = ""
    h_host: str = ""              # transport-level Host header (xhttp/ws)
    mode: str = ""                # xhttp: auto, packet-up, stream-up, stream-one
    extra: str = ""               # xhttp raw JSON blob
    service_name: str = ""        # grpc
    authority: str = ""           # grpc

    raw: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Vless":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def parse(uri: str) -> Vless:
    s = uri.strip()
    if not s.startswith("vless://"):
        raise ValueError("not a vless link")

    u = urlparse(s)
    if not u.username:
        raise ValueError("missing uuid")
    if not u.hostname:
        raise ValueError("missing host")
    if u.port is None:
        raise ValueError("missing port")
    if u.port < 1 or u.port > 65535:
        raise ValueError(f"port {u.port} out of range 1-65535")

    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}

    def g(k, d=""):
        return unquote(q.get(k, d)) if q.get(k) is not None else d

    net = g("type", "tcp")
    if net == "raw":
        net = "tcp"

    v = Vless(
        uuid=unquote(u.username),
        host=u.hostname,
        port=u.port,
        name=unquote(u.fragment) if u.fragment else "",
        network=net,
        security=g("security", "none") or "none",
        encryption=g("encryption", "none") or "none",
        flow=g("flow"),
        sni=g("sni"),
        fp=g("fp"),
        alpn=g("alpn"),
        pbk=g("pbk"),
        sid=g("sid"),
        spx=g("spx"),
        pqv=g("pqv"),
        path=g("path"),
        h_host=g("host"),
        mode=g("mode"),
        extra=g("extra"),
        service_name=g("serviceName"),
        authority=g("authority"),
        raw=s,
    )
    return v
