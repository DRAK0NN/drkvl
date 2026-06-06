import urllib.request
from pathlib import Path
from typing import Optional

from . import profile
from .util import info, warn

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
    for d in [profile.ASSETS, *SYSTEM_DIRS]:
        if _has_all(d):
            return d
    return None


def ensure() -> Path:
    d = find()
    if d:
        return d

    profile.ASSETS.mkdir(parents=True, exist_ok=True)
    profile.chown_user(profile.ASSETS)
    for name, url in SOURCES.items():
        target = profile.ASSETS / name
        if target.exists() and target.stat().st_size > 0:
            continue
        info(f"downloading {name} from v2fly")
        tmp = target.with_suffix(target.suffix + ".part")
        try:
            urllib.request.urlretrieve(url, tmp)
            tmp.rename(target)
        except Exception as e:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"failed to download {name}: {e}")
        profile.chown_user(target)

    return profile.ASSETS
