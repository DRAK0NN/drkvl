"""Profile and JSON persistence — reading and writing drkvl state on disk."""
import json
import os
import re
from pathlib import Path
from typing import Optional

from . import link, ownership, paths
from .link import Profile

_safe = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(s: str) -> str:
    """Sanitise an arbitrary label into a safe profile-filename stem."""
    s = _safe.sub("-", s.strip()).strip("-")
    s = s.replace("..", "").strip("-.")
    return s.lower() or "profile"


def _path(name: str) -> Path:
    """Return the on-disk path of the profile named ``name``."""
    return paths.PROFILES / f"{name}.json"


def read_json(p: Path) -> Optional[dict]:
    """Load JSON from ``p``; return None if missing, or warn and return None if corrupt."""
    if not p.exists():
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        from .util import warn
        warn(f"{p.name} is corrupt/unreadable, ignoring: {e}")
        return None


def write_text(p: Path, text: str, mode: int = 0o600) -> None:
    """Write plain ``text`` to ``p`` (mode 0600, refusing symlinks, chowned to the user)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    ownership.chown_user(p)


def write_json(p: Path, data: dict, mode: int = 0o600) -> None:
    """Write ``data`` as indented JSON to ``p`` (mode 0600, refusing symlinks)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    ownership.chown_user(p)


def clear(p: Path) -> None:
    """Remove ``p`` if present; silently ignore a missing file."""
    try:
        p.unlink()
    except FileNotFoundError:
        pass


def list_all() -> list[tuple[str, Profile]]:
    """Return ``(name, profile)`` for every saved profile, skipping unreadable ones.

    Each profile reconstructs into the right class (Vless or Hy2) via
    :func:`drkvl.link.from_dict`, keyed by its persisted ``kind``.
    """
    if not paths.PROFILES.exists():
        return []
    out = []
    for p in sorted(paths.PROFILES.glob("*.json")):
        try:
            with open(p) as f:
                out.append((p.stem, link.from_dict(json.load(f))))
        except Exception as e:
            from .util import warn
            warn(f"skipping unreadable profile {p.name}: {e}")
            continue
    return out


def count() -> int:
    """Cheaply count saved profiles without parsing them (used by the banner)."""
    if not paths.PROFILES.exists():
        return 0
    return sum(1 for _ in paths.PROFILES.glob("*.json"))


def save(v: Profile, name: Optional[str] = None) -> str:
    """Persist ``v`` to a uniquely-named profile file; return the stem used."""
    ownership.ensure_dirs()
    if not name:
        name = _slug(v.name) if v.name else f"{v.host}-{v.port}"
    name = _slug(name)

    target = _path(name)
    i = 2
    while target.exists():
        target = _path(f"{name}-{i}")
        i += 1

    fd = os.open(str(target),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(v.to_dict(), f, indent=2)

    from . import state
    if state.get_default() is None:
        state.set_default_name(target.stem)
    return target.stem


def load(name: Optional[str] = None) -> tuple[str, Profile]:
    """Resolve ``name`` (or the default profile) to ``(name, profile)``.

    ``name`` may be a profile name or a numeric index; an exact name match
    takes precedence so an all-digit profile name stays loadable.
    """
    items = list_all()
    if not items:
        raise FileNotFoundError("no profiles")

    if name is None:
        from . import state
        name = state.get_default() or items[0][0]

    for n, v in items:
        if n == name:
            return n, v

    if name.isdigit():
        idx = int(name)
        if not (0 <= idx < len(items)):
            raise IndexError(f"index {idx} out of range")
        return items[idx]

    raise FileNotFoundError(f"profile {name!r} not found")


def remove(name: str) -> str:
    """Delete the profile resolved from ``name``; repoint the default if needed."""
    n, _ = load(name)
    _path(n).unlink()
    from . import state
    if state.get_default() == n:
        rest = [stem for stem, _ in list_all()]
        if rest:
            state.set_default_name(rest[0])
        else:
            state.clear_default()
    return n
