import shutil
import urllib.request
from pathlib import Path
from typing import Optional

from . import ownership, paths
from .util import info

# v2fly publishes canonical geosite (`category-ru`, `category-cn`, etc.)
# and geoip data. xray reads them as `geosite.dat` / `geoip.dat`.
SOURCES = {
    "geosite.dat":
        "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
    "geoip.dat":
        "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
}

SYSTEM_DIRS = [
    Path("/usr/local/share/xray"),
    Path("/usr/share/xray"),
    Path("/opt/share/xray"),
]

NAMES = tuple(SOURCES.keys())


def _has_all(d: Path) -> bool:
    return all((d / n).exists() and (d / n).stat().st_size > 0 for n in NAMES)


def find() -> Optional[Path]:
    """Return a directory holding both geo .dat files, or None if none has them."""
    for d in [paths.ASSETS, *SYSTEM_DIRS]:
        if _has_all(d):
            return d
    return None


def ensure() -> Path:
    """Return a dir with the geo assets, downloading them from v2fly if absent."""
    d = find()
    if d:
        return d

    paths.ASSETS.mkdir(parents=True, exist_ok=True)
    ownership.chown_user(paths.ASSETS)
    for name, url in SOURCES.items():
        target = paths.ASSETS / name
        if target.exists() and target.stat().st_size > 0:
            continue
        info(f"downloading {name} from v2fly")
        tmp = target.with_suffix(target.suffix + ".part")
        try:
            # timeout so a stalled mirror can't hang the whole CLI forever
            with urllib.request.urlopen(url, timeout=30) as resp, \
                    open(tmp, "wb") as out:
                shutil.copyfileobj(resp, out)
            tmp.rename(target)
        except Exception as e:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"failed to download {name}: {e}")
        ownership.chown_user(target)

    return paths.ASSETS
