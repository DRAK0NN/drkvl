from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, unquote


@dataclass
class Vless:
    """A parsed vless:// link: identity, transport, security and their params."""

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
        """Return this link as a plain dict for JSON persistence."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Vless":
        """Build a Vless from a dict, ignoring unknown keys."""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def parse(uri: str) -> Vless:
    """Parse a ``vless://`` URI into a :class:`Vless`; raise ValueError if malformed."""
    s = uri.strip()
    if not s.startswith("vless://"):
        raise ValueError("not a vless link")

    u = urlparse(s)
    if not u.username:
        raise ValueError("missing uuid")
    if not u.hostname:
        raise ValueError("missing host")
    # urlparse defers port parsing until .port is accessed; a non-numeric
    # port raises urllib's own ValueError there. Translate it into our own
    # message so the user sees guidance, not "Port could not be cast ...".
    try:
        port = u.port
    except ValueError:
        raise ValueError("invalid port (must be a number between 1 and 65535)")
    if port is None:
        raise ValueError("missing port")
    if port < 1 or port > 65535:
        raise ValueError(f"port {port} out of range 1-65535")

    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}

    # parse_qs already percent-decodes values; do NOT unquote a second time.
    def g(k: str, d: str = "") -> str:
        """Return query param ``k`` (already decoded), or default ``d``."""
        val = q.get(k)
        return val if val is not None else d

    net = g("type", "tcp") or "tcp"
    if net == "raw":
        net = "tcp"

    v = Vless(
        uuid=unquote(u.username),
        host=u.hostname,
        port=port,
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
