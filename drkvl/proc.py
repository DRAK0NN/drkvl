import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from . import profile
from .util import have

XRAY_PID = profile.HOME / "xray.pid"
TUN2SOCKS_PID = profile.HOME / "tun2socks.pid"
XRAY_LOG = profile.HOME / "xray.log"
TUN2SOCKS_LOG = profile.HOME / "tun2socks.log"


def _read_pid(p: Path) -> Optional[int]:
    try:
        return int(p.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False


def _start(name: str, argv: list[str], pidfile: Path, log: Path,
           env: Optional[dict] = None) -> int:
    if not have(argv[0]):
        raise RuntimeError(f"{argv[0]} not found in PATH")

    pid = _read_pid(pidfile)
    if pid and _alive(pid):
        raise RuntimeError(f"{name} already running (pid {pid})")

    profile.HOME.mkdir(parents=True, exist_ok=True)
    logf = open(log, "wb")
    sub_env = None
    if env:
        sub_env = os.environ.copy()
        sub_env.update(env)
    p = subprocess.Popen(
        argv,
        stdout=logf,
        stderr=logf,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=sub_env,
    )
    time.sleep(0.3)
    if p.poll() is not None:
        raise RuntimeError(f"{name} exited immediately (see {log})")

    pidfile.write_text(str(p.pid))
    return p.pid


def start_xray(config_path: Path, asset_dir: Optional[Path] = None) -> int:
    env = {"XRAY_LOCATION_ASSET": str(asset_dir)} if asset_dir else None
    return _start("xray",
                  ["xray", "run", "-c", str(config_path)],
                  XRAY_PID, XRAY_LOG, env=env)


def start_tun2socks(device: str, socks_port: int, mtu: int = 1500) -> int:
    return _start("tun2socks",
                  ["tun2socks",
                   "-device", f"tun://{device}",
                   "-proxy", f"socks5://127.0.0.1:{socks_port}",
                   "-mtu", str(mtu),
                   "-loglevel", "warn"],
                  TUN2SOCKS_PID, TUN2SOCKS_LOG)


def _stop(pidfile: Path) -> bool:
    pid = _read_pid(pidfile)
    if pid is None:
        return False
    killed = False
    if _alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.1)
                if not _alive(pid):
                    break
            else:
                os.kill(pid, signal.SIGKILL)
            killed = True
        except ProcessLookupError:
            pass
        except PermissionError:
            # pid file refers to a process we can't signal — try sudo
            # nothing, leave it; caller should be root for stop ops.
            pass
    try:
        pidfile.unlink()
    except FileNotFoundError:
        pass
    return killed


def stop_xray() -> bool:
    return _stop(XRAY_PID)


def stop_tun2socks() -> bool:
    return _stop(TUN2SOCKS_PID)


def xray_running() -> bool:
    pid = _read_pid(XRAY_PID)
    return pid is not None and _alive(pid)


def tun2socks_running() -> bool:
    pid = _read_pid(TUN2SOCKS_PID)
    return pid is not None and _alive(pid)
