"""Selection and session state: the default profile and the active connection."""
from typing import Optional

from . import ownership, paths, storage


def get_default() -> Optional[str]:
    """Return the default profile name, or None when none is set."""
    if paths.DEFAULT.exists():
        return paths.DEFAULT.read_text().strip()
    return None


def set_default_name(name: str) -> None:
    """Record ``name`` as the default profile without validating it.

    Uses the same O_NOFOLLOW + chown-to-user write as the rest of the state so a
    root-created default file stays readable/writable by the unprivileged user.
    """
    storage.write_text(paths.DEFAULT, name)


def clear_default() -> None:
    """Forget the default profile."""
    storage.clear(paths.DEFAULT)


def set_default(name: str) -> None:
    """Validate ``name`` against the saved profiles and make it the default."""
    n, _ = storage.load(name)
    ownership.ensure_dirs()
    set_default_name(n)


def read_active() -> Optional[dict]:
    """Return the active-connection record, or None when not connected."""
    return storage.read_json(paths.ACTIVE)


def write_active(data: dict) -> None:
    """Persist the active-connection record."""
    storage.write_json(paths.ACTIVE, data)


def clear_active() -> None:
    """Remove the active-connection record."""
    storage.clear(paths.ACTIVE)
