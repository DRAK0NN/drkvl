import os
import shutil
import socket
import sys


def have(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def fmt_bytes(n: int | float) -> str:
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:.1f}{u}" if u != "B" else f"{int(n)}{u}"
        n /= 1024
    return f"{n:.1f}P"


def fmt_duration(secs: float) -> str:
    s = int(secs)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{sec:02d}s"
    return f"{sec}s"


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def isatty() -> bool:
    return sys.stdout.isatty()


def c(code: str, s: str) -> str:
    if not isatty() or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def info(s: str) -> None:
    print(f"{c('32', '::')} {s}")


def warn(s: str) -> None:
    print(c("33", f"!! {s}"), file=sys.stderr)


def err(s: str) -> None:
    print(c("31", f"!! {s}"), file=sys.stderr)


def resolve_host(host: str) -> str:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise RuntimeError(f"cannot resolve {host}: {e}")
