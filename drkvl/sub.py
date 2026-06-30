"""Subscription support: fetch a base64/plain list of vless:// links from a URL.

A subscription body is usually base64 of newline-joined proxy links (often a
mix of protocols). We decode it, keep only the ``vless://`` links, save them as
``sub-N`` profiles, and remember which profile names came from which URL in
``subscriptions.json`` so updates can replace exactly that subscription's set.
"""
import base64
import binascii
import re
import urllib.parse
import urllib.request

from . import paths, storage
from .link import Vless, parse
from .util import warn

TIMEOUT = 10
MAX_BYTES = 4 * 1024 * 1024   # cap untrusted subscription bodies at 4 MiB

_SUB_RE = re.compile(r"^sub-(\d+)$")


def decode_body(raw: bytes) -> str:
    """Decode a subscription body to a newline-separated link list.

    Returns plain text unchanged if it already contains links, otherwise tries
    standard then url-safe base64. Raises ValueError if it is neither.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    if "://" in text:
        return text
    compact = "".join(text.split())
    padded = compact + "=" * (-len(compact) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = dec(padded).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            continue
        if "://" in decoded:
            return decoded
    raise ValueError("subscription body is not valid base64 or a link list")


def fetch(url: str, timeout: int = TIMEOUT) -> str:
    """Download ``url`` and return its decoded link list.

    Only http/https are accepted (no file://, ftp://, ...). The download is
    bounded by ``timeout`` seconds and ``MAX_BYTES`` so a malicious or broken
    endpoint can't read local files or exhaust memory.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise RuntimeError(
            f"unsupported subscription URL scheme {scheme or '(none)'!r}; use http/https")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read(MAX_BYTES + 1)
    except Exception as e:
        raise RuntimeError(f"failed to fetch subscription: {e}")
    if len(raw) > MAX_BYTES:
        raise RuntimeError(f"subscription body too large (> {MAX_BYTES // (1024 * 1024)} MiB)")
    if not raw or not raw.strip():
        raise RuntimeError("subscription returned an empty response")
    try:
        return decode_body(raw)
    except ValueError as e:
        raise RuntimeError(str(e))


def parse_links(body: str) -> tuple[list[Vless], int]:
    """Parse decoded ``body`` into Vless objects; return (vless, n_skipped).

    Non-vless protocols (vmess/trojan/ss/...) and malformed vless links are
    skipped with a warning and counted in ``n_skipped``.
    """
    vless: list[Vless] = []
    skipped = 0
    seen: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith("vless://"):
            if "://" in line:
                proto = line.split("://", 1)[0]
                warn(f"skipping unsupported {proto}:// link")
                skipped += 1
            continue
        if line in seen:           # drop duplicate links from the subscription
            continue
        seen.add(line)
        try:
            vless.append(parse(line))
        except ValueError as e:
            warn(f"skipping malformed vless link: {e}")
            skipped += 1
    return vless, skipped


def next_index() -> int:
    """Return the next free ``sub-N`` index given the profiles already on disk."""
    mx = -1
    for stem, _ in storage.list_all():
        m = _SUB_RE.match(stem)
        if m:
            mx = max(mx, int(m.group(1)))
    return mx + 1


def add_profiles(vlesses: list[Vless]) -> list[str]:
    """Save each Vless as ``sub-N`` (continuing the global index); return the names."""
    idx = next_index()
    names = []
    for v in vlesses:
        names.append(storage.save(v, name=f"sub-{idx}"))
        idx += 1
    return names


def remove_names(names: list[str]) -> None:
    """Delete the named profiles, ignoring any that are already gone."""
    for n in names:
        try:
            storage.remove(n)
        except (FileNotFoundError, IndexError):
            pass


def remove_all() -> int:
    """Delete every ``sub-N`` profile; return how many were removed."""
    n = 0
    for stem, _ in list(storage.list_all()):
        if _SUB_RE.match(stem):
            try:
                storage.remove(stem)
                n += 1
            except (FileNotFoundError, IndexError):
                pass
    return n


def load_map() -> dict:
    """Return the ``{url: [profile names]}`` subscription map (empty if none)."""
    data = storage.read_json(paths.SUBSCRIPTIONS)
    return data if isinstance(data, dict) else {}


def save_map(m: dict) -> None:
    """Persist the subscription map."""
    storage.write_json(paths.SUBSCRIPTIONS, m)


def saved_urls() -> list[str]:
    """Return all remembered subscription URLs."""
    return list(load_map().keys())


def url_profiles(url: str) -> list[str]:
    """Return the profile names previously added from ``url``."""
    return load_map().get(url, [])


def set_url_profiles(url: str, names: list[str]) -> None:
    """Record that ``url`` currently owns ``names``."""
    m = load_map()
    m[url] = names
    save_map(m)


def forget_url(url: str) -> None:
    """Remove ``url`` from the subscription map."""
    m = load_map()
    m.pop(url, None)
    save_map(m)
