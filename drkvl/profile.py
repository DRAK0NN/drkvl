import json
import os
import pwd
import re
from pathlib import Path
from typing import Optional

from .link import Vless


def _real_home() -> Path:
    # under sudo, point at the invoking user's home so state is shared
    # between privileged (up/down) and unprivileged (add/list) calls.
    su = os.environ.get("SUDO_USER")
    if su and os.geteuid() == 0:
        try:
            return Path(pwd.getpwnam(su).pw_dir)
        except KeyError:
            pass
    return Path.home()


HOME = Path(os.environ.get("DRKVL_HOME", _real_home() / ".config" / "drkvl"))
PROFILES = HOME / "profiles"
ACTIVE = HOME / "active.json"
BACKUP = HOME / "backup_routes.json"
RESOLV_BAK = HOME / "resolv.conf.bak"
XRAY_CONFIG = HOME / "xray_config.json"
ASSETS = HOME / "assets"
DEFAULT = HOME / "default"

_safe = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(s: str) -> str:
    s = _safe.sub("-", s.strip()).strip("-")
    return s.lower() or "profile"


def _sudo_owner() -> Optional[tuple[int, int]]:
    su = os.environ.get("SUDO_USER")
    if not su or os.geteuid() != 0:
        return None
    try:
        e = pwd.getpwnam(su)
        return e.pw_uid, e.pw_gid
    except KeyError:
        return None


def chown_user(p: Path) -> None:
    owner = _sudo_owner()
    if not owner:
        return
    try:
        os.chown(p, owner[0], owner[1])
    except OSError:
        pass


def ensure_dirs() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    chown_user(HOME)
    PROFILES.mkdir(parents=True, exist_ok=True)
    chown_user(PROFILES)


def _path(name: str) -> Path:
    return PROFILES / f"{name}.json"


def list_all() -> list[tuple[str, Vless]]:
    if not PROFILES.exists():
        return []
    out = []
    for p in sorted(PROFILES.glob("*.json")):
        try:
            with open(p) as f:
                out.append((p.stem, Vless.from_dict(json.load(f))))
        except Exception:
            continue
    return out


def save(v: Vless, name: Optional[str] = None) -> str:
    ensure_dirs()
    if not name:
        name = _slug(v.name) if v.name else f"{v.host}-{v.port}"
    name = _slug(name)

    target = _path(name)
    i = 2
    while target.exists():
        target = _path(f"{name}-{i}")
        i += 1

    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(v.to_dict(), f, indent=2)

    if not DEFAULT.exists():
        DEFAULT.write_text(target.stem)

    return target.stem


def load(name: Optional[str] = None) -> tuple[str, Vless]:
    items = list_all()
    if not items:
        raise FileNotFoundError("no profiles")

    if name is None:
        if DEFAULT.exists():
            name = DEFAULT.read_text().strip()
        else:
            name = items[0][0]

    if name.isdigit():
        idx = int(name)
        if not (0 <= idx < len(items)):
            raise IndexError(f"index {idx} out of range")
        return items[idx]

    for n, v in items:
        if n == name:
            return n, v
    raise FileNotFoundError(f"profile {name!r} not found")


def remove(name: str) -> str:
    n, _ = load(name)
    _path(n).unlink()
    if DEFAULT.exists() and DEFAULT.read_text().strip() == n:
        DEFAULT.unlink()
        rest = list_all()
        if rest:
            DEFAULT.write_text(rest[0][0])
    return n


def set_default(name: str) -> None:
    n, _ = load(name)
    ensure_dirs()
    DEFAULT.write_text(n)


def read_json(p: Path) -> Optional[dict]:
    if not p.exists():
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def write_json(p: Path, data: dict, mode: int = 0o644) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    chown_user(p)


def clear(p: Path) -> None:
    try:
        p.unlink()
    except FileNotFoundError:
        pass
