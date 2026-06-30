"""Ownership and permissions for drkvl's state files.

Under sudo drkvl runs as root while the config dir belongs to the invoking
user, so new files are chowned back to them and the runtime dir is kept
owner-only.
"""
import os
import pwd
from pathlib import Path
from typing import Optional

from . import paths


def _sudo_owner() -> Optional[tuple[int, int]]:
    """Return ``(uid, gid)`` of the invoking SUDO_USER, or None when not under sudo."""
    su = os.environ.get("SUDO_USER")
    if not su or os.geteuid() != 0:
        return None
    try:
        e = pwd.getpwnam(su)
        return e.pw_uid, e.pw_gid
    except KeyError:
        return None


def chown_user(p: Path) -> None:
    """chown ``p`` to the invoking SUDO_USER; a no-op when not running under sudo."""
    owner = _sudo_owner()
    if not owner:
        return
    try:
        os.chown(p, owner[0], owner[1])
    except OSError:
        pass


def private_dir(p: Path) -> None:
    """Create directory ``p`` and make it owner-only (mode 0700)."""
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass


def ensure_dirs() -> None:
    """Create HOME and PROFILES as private dirs owned by the invoking user."""
    private_dir(paths.HOME)
    chown_user(paths.HOME)
    private_dir(paths.PROFILES)
    chown_user(paths.PROFILES)
