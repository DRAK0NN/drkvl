"""Filesystem locations for drkvl state — the single source of truth.

Every module reads these as ``paths.X`` (never ``from .paths import X``) so a
test can monkeypatch a temporary location and have it seen everywhere.
"""
import os
import pwd
from pathlib import Path


def _real_home() -> Path:
    """Return the invoking user's home directory, even under sudo.

    Under ``sudo`` the privileged (up/down) and unprivileged (add/list) calls
    must share state, so point at SUDO_USER's home rather than root's.
    """
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
SUBSCRIPTIONS = HOME / "subscriptions.json"
