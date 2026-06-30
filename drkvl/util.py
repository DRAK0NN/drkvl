import os
import shutil
import socket
import sys


def have(bin_name: str) -> bool:
    """Return whether ``bin_name`` is found on PATH."""
    return shutil.which(bin_name) is not None


def fmt_bytes(n: int | float) -> str:
    """Format a byte count as a short human string (e.g. ``1.5M``)."""
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024:
            return f"{n:.1f}{u}" if u != "B" else f"{int(n)}{u}"
        n /= 1024
    return f"{n:.1f}P"


def fmt_duration(secs: float) -> str:
    """Format a duration in seconds as a compact string (e.g. ``1h05m``)."""
    s = int(secs)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{sec:02d}s"
    return f"{sec}s"


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Return whether a TCP connection to ``host:port`` succeeds within 0.5s."""
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
    """Return whether stdout is a terminal."""
    return sys.stdout.isatty()


def c(code: str, s: str) -> str:
    """Wrap ``s`` in ANSI colour ``code``, unless output is not a tty or NO_COLOR is set."""
    if not isatty() or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def info(s: str) -> None:
    """Print an informational ``::`` line to stdout."""
    print(f"{c('32', '::')} {s}")


def warn(s: str) -> None:
    """Print a warning ``!!`` line to stderr."""
    print(c("33", f"!! {s}"), file=sys.stderr)


def err(s: str) -> None:
    """Print an error ``!!`` line to stderr."""
    print(c("31", f"!! {s}"), file=sys.stderr)


def resolve_host(host: str) -> str:
    """Resolve ``host`` to an IPv4 address (or return it if already one)."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise RuntimeError(
            f"cannot resolve host '{host}' — check the server address in the "
            f"profile and that DNS/network is reachable")
