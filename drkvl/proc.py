import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from . import ownership, paths
from .util import have

XRAY_PID = paths.HOME / "xray.pid"
TUN2SOCKS_PID = paths.HOME / "tun2socks.pid"
XRAY_LOG = paths.HOME / "xray.log"
TUN2SOCKS_LOG = paths.HOME / "tun2socks.log"


def _read_pid(p: Path) -> Optional[int]:
    try:
        return int(p.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _comm(pid: int) -> Optional[str]:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return None


def _alive(pid: int, name: Optional[str] = None) -> bool:
    # a pidfile can outlive its process; if the PID was recycled by an
    # unrelated process, treat it as dead so we never signal a stranger.
    try:
        os.kill(pid, 0)
    except PermissionError:
        pass               # exists but not ours to signal
    except ProcessLookupError:
        return False
    if name is not None and _comm(pid) != name[:15]:   # comm capped at 15
        return False
    return True


def _start(name: str, argv: list[str], pidfile: Path, log: Path,
           env: Optional[dict] = None) -> int:
    if not have(argv[0]):
        raise RuntimeError(f"{argv[0]} not found in PATH")

    pid = _read_pid(pidfile)
    if pid and _alive(pid, os.path.basename(argv[0])):
        raise RuntimeError(f"{name} already running (pid {pid})")

    ownership.private_dir(paths.HOME)
    sub_env = None
    if env:
        sub_env = os.environ.copy()
        sub_env.update(env)
    # O_NOFOLLOW: refuse to write through a pre-planted symlink (the log dir
    # is chowned to the unprivileged user while we run as root).
    fd = os.open(str(log),
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as logf:
        p = subprocess.Popen(
            argv,
            stdout=logf,
            stderr=logf,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=sub_env,
        )
    time.sleep(0.15)
    if p.poll() is not None:
        raise RuntimeError(f"{name} exited immediately (see {log})")

    pidfile.write_text(str(p.pid))
    return p.pid


def start_xray(config_path: Path, asset_dir: Optional[Path] = None) -> int:
    """Start xray with ``config_path``; return its PID. Raise on failure."""
    env = {"XRAY_LOCATION_ASSET": str(asset_dir)} if asset_dir else None
    return _start("xray",
                  ["xray", "run", "-c", str(config_path)],
                  XRAY_PID, XRAY_LOG, env=env)


def _t2s_argv(device: str, socks_port: int, mtu: int, level: str) -> list[str]:
    return ["tun2socks",
            "-device", f"tun://{device}",
            "-proxy", f"socks5://127.0.0.1:{socks_port}",
            "-mtu", str(mtu),
            "-loglevel", level]


def start_tun2socks(device: str, socks_port: int, mtu: int = 1500) -> int:
    """Start tun2socks on ``device`` forwarding to the local socks port; return its PID."""
    # tun2socks <2.5 wants "warn", >=2.5 wants "warning". Retry with the other
    # spelling ONLY when the loglevel itself was rejected; every other failure
    # (missing binary, already running, real startup crash) must surface as-is
    # instead of wasting a second attempt that truncates the log and masks the
    # real cause the user is told to read.
    try:
        return _start("tun2socks",
                      _t2s_argv(device, socks_port, mtu, "warn"),
                      TUN2SOCKS_PID, TUN2SOCKS_LOG)
    except RuntimeError as e:
        log = TUN2SOCKS_LOG.read_text(errors="replace") if TUN2SOCKS_LOG.exists() else ""
        rejected = "unrecognized level" in log.lower() or "not a valid" in log.lower()
        if "exited immediately" not in str(e) or not rejected:
            raise
        return _start("tun2socks",
                      _t2s_argv(device, socks_port, mtu, "warning"),
                      TUN2SOCKS_PID, TUN2SOCKS_LOG)


def _stop(pidfile: Path, name: Optional[str] = None) -> bool:
    pid = _read_pid(pidfile)
    if pid is None:
        return False
    killed = False
    if _alive(pid, name):
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
    """Stop xray (SIGTERM then SIGKILL); return whether a process was signalled."""
    return _stop(XRAY_PID, "xray")


def stop_tun2socks() -> bool:
    """Stop tun2socks (SIGTERM then SIGKILL); return whether a process was signalled."""
    return _stop(TUN2SOCKS_PID, "tun2socks")


def xray_running() -> bool:
    """Return whether the recorded xray process is alive and really xray."""
    pid = _read_pid(XRAY_PID)
    return pid is not None and _alive(pid, "xray")


def tun2socks_running() -> bool:
    """Return whether the recorded tun2socks process is alive and really tun2socks."""
    pid = _read_pid(TUN2SOCKS_PID)
    return pid is not None and _alive(pid, "tun2socks")
