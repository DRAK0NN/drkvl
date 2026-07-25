import base64
import binascii
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, unquote


@dataclass
class Vless:
    """A parsed vless:// link: identity, transport, security and their params."""

    uuid: str
    host: str
    port: int
    name: str = ""
    kind: str = "vless"           # profile-type discriminator (see link.from_dict)

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
    if not s.lower().startswith("vless://"):
        raise ValueError("not a vless link")

    # peel userinfo ourselves before urlparse (see parse_hy2): a bare '/' in the
    # identity is RFC-3986-illegal in userinfo, and urlparse then ends the
    # authority at it so .port comes back None. UUIDs never contain '/', but a
    # trojan-style secret in this position would, so hand only host:port on.
    after = s.split("://", 1)[1]
    after, _, frag = after.partition("#")
    authority, _, query = after.partition("?")
    userinfo, at, hostport = authority.rpartition("@")
    if not at or not userinfo:
        raise ValueError("missing uuid")

    u = urlparse("vless://" + hostport)
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

    q = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}

    # parse_qs already percent-decodes values; do NOT unquote a second time.
    def g(k: str, d: str = "") -> str:
        """Return query param ``k`` (already decoded), or default ``d``."""
        val = q.get(k)
        return val if val is not None else d

    net = g("type", "tcp") or "tcp"
    if net == "raw":
        net = "tcp"

    v = Vless(
        uuid=unquote(userinfo),
        host=u.hostname,
        port=port,
        name=unquote(frag) if frag else "",
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


@dataclass
class Hy2:
    """A parsed ``hysteria2://`` link, emitted as an xray native hysteria outbound.

    Kept separate from :class:`Vless` because hysteria's fields (auth, obfs,
    cert pin, udp port-hopping) barely overlap; ``network``/``security`` are
    fixed so ``list``/``status`` render it uniformly alongside vless profiles.
    """

    auth: str
    host: str
    port: int
    name: str = ""
    kind: str = "hy2"

    network: str = "hysteria"     # constant; for uniform display with Vless
    security: str = "tls"

    sni: str = ""
    insecure: bool = False        # accepted from the link; see cmd_add (allowInsecure
                                  # was removed from xray — honoured only via pin)
    pin_sha256: str = ""          # hex (colons ok) -> tlsSettings.pinnedPeerCertSha256

    obfs: str = ""                # "" or "salamander"
    obfs_password: str = ""

    ports: str = ""               # udphop range, e.g. "20000-40000"
    hop_interval: int = 0         # udphop interval (seconds); 0 = omit

    raw: str = ""

    def to_dict(self) -> dict:
        """Return this link as a plain dict for JSON persistence."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Hy2":
        """Build an Hy2 from a dict, ignoring unknown keys."""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


Profile = Vless | Hy2


def _norm_pin(pin: str) -> str:
    """Normalise a pinSHA256 to the hex form xray's TLS layer accepts.

    Verified against xray's ``TLSConfig.Build`` (infra/conf): each pin is
    ``hex.DecodeString(ReplaceAll(v, ":", ""))`` and must be 32 bytes. So the
    accepted form is a 64-char SHA-256 in HEX, case-insensitive, with optional
    OpenSSL-style colons (``AA:BB:..``); base64 is NOT accepted. Hysteria links
    carry the pin as colon-hex or base64, so we pass hex/colon-hex through
    unchanged and decode a base64 pin to hex; anything else is left for xray to
    reject.
    """
    pin = pin.strip()
    if not pin:
        return ""
    stripped = pin.replace(":", "")
    if stripped and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return pin
    try:
        raw = base64.b64decode(pin + "=" * (-len(pin) % 4))
    except (binascii.Error, ValueError):
        return pin
    return raw.hex() if len(raw) == 32 else pin


def parse_hy2(uri: str) -> Hy2:
    """Parse a ``hysteria2://`` (or ``hy2://``) URI into an :class:`Hy2`.

    Raises ValueError if malformed. ``auth`` is the full userinfo
    (``user[:pass]``) or the ``?auth=`` query param.

    Panels put a raw standard-base64 auth in the userinfo, and that alphabet
    includes ``+``, ``/`` and ``=``. RFC-3986 forbids a bare ``/`` in userinfo
    (it must be %2F-encoded), so urlparse ends the authority at that ``/`` — the
    real ``host:port`` slides into ``.path`` and ``.port`` comes back None (or
    raises, if the truncated authority holds a stray ``:``). So we peel the
    userinfo off ourselves at the last ``@`` and hand only ``host:port`` to
    urlparse. For the same reason ``auth`` / ``obfs-password`` are decoded with
    ``unquote`` (``%XX`` decoded, a bare ``+`` kept literal as base64 data),
    while all other params keep standard query semantics where ``+`` is a space.
    """
    s = uri.strip()
    if not s.lower().startswith(("hysteria2://", "hy2://")):
        raise ValueError("not a hysteria2 link")

    # split by hand: base64 auth, host and port contain neither '#' nor '?',
    # and the fragment is the last component, so these partitions are safe.
    after = s.split("://", 1)[1]
    after, _, frag = after.partition("#")
    authority, _, query = after.partition("?")
    userinfo, at, hostport = authority.rpartition("@")

    u = urlparse("hysteria2://" + hostport)
    if not u.hostname:
        raise ValueError("missing host")
    try:
        port = u.port
    except ValueError:
        raise ValueError("invalid port (must be a number between 1 and 65535)")
    if port is None:
        raise ValueError("missing port")
    if port < 1 or port > 65535:
        raise ValueError(f"port {port} out of range 1-65535")

    q = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}

    def g(k: str, d: str = "") -> str:
        """Return query param ``k`` (parse_qs semantics: ``+`` -> space), or ``d``."""
        val = q.get(k)
        return val if val is not None else d

    def gplus(k: str) -> str:
        """Return raw query param ``k`` with a bare ``+`` kept literal (base64-safe)."""
        for kv in query.split("&"):
            key, eq, val = kv.partition("=")
            if key == k:
                return unquote(val)
        return ""

    # userinfo may be user:pass; unquote each half so a bare '+' in a base64
    # secret survives (unquote_plus / parse_qs would turn it into a space).
    auth = ""
    if at and userinfo:
        user, colon, pw = userinfo.partition(":")
        auth = unquote(user) + (":" + unquote(pw) if colon else "")
    if not auth:
        auth = gplus("auth")
    if not auth:
        raise ValueError("missing auth (password)")

    interval = g("hopInterval")
    return Hy2(
        auth=auth,
        host=u.hostname,
        port=port,
        name=unquote(frag) if frag else "",
        sni=g("sni") or g("peer"),
        insecure=g("insecure").lower() in ("1", "true", "yes"),
        pin_sha256=_norm_pin(g("pinSHA256") or g("pinsha256")),
        obfs=g("obfs"),
        obfs_password=gplus("obfs-password") or gplus("obfs_password"),
        ports=(g("mport") or g("ports")).strip(),
        hop_interval=int(interval) if interval.isdigit() else 0,
        raw=s,
    )


def parse_any(uri: str) -> Profile:
    """Parse any supported proxy URI (``vless://`` or ``hysteria2://``).

    Scheme matching is case-insensitive (RFC-3986 schemes are), matching the
    subscription filter so an uppercase-scheme link is never misrouted.
    """
    s = uri.strip()
    if s.lower().startswith(("hysteria2://", "hy2://")):
        return parse_hy2(s)
    return parse(s)


def from_dict(d: dict) -> Profile:
    """Reconstruct the right profile class from a persisted dict, keyed by ``kind``."""
    if d.get("kind") == "hy2":
        return Hy2.from_dict(d)
    return Vless.from_dict(d)
