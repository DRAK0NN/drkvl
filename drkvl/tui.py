import os
import re
import shlex
import sys
import time

from . import __version__, display, proc, stats, storage
from .util import isatty


def _c(code, s):
    if not isatty() or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def _red(s): return _c("1;31", s)
def _green(s): return _c("32", s)
def _yellow(s): return _c("33", s)
def _dim(s): return _c("2", s)


_TITLE = [
    r" _____     _____     _    __  __      __   _      ",
    r"|  __ \   |  __ \   | |  / /  \ \    / /  | |     ",
    r"| |  | |  | |__) |  | | / /    \ \  / /   | |     ",
    r"| |  | |  |  _  /   |  <        \ \/ /    | |     ",
    r"| |__| |  | | \ \   | | \ \      \  /     | |____ ",
    r"|_____/   |_|  \_\  |_|  \_\      \/      |______|",
]


def _termwidth():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


_ANSI_RE = re.compile(r"\033\[[^m]*m")


def _vislen(s):
    return len(_ANSI_RE.sub("", s))


def _banner():
    print("\033[2J\033[H", end="")

    n = storage.count()
    xr, t2 = proc.xray_running(), proc.tun2socks_running()
    st = "on" if (xr and t2) else ("partial" if (xr or t2) else "off")
    st_c = _green(st) if st == "on" else (_yellow(st) if st == "partial" else _dim(st))

    tw = _termwidth()
    title_w = max(len(l) for l in _TITLE)
    pad = max(0, (tw - title_w) // 2)

    lines = []
    for l in _TITLE:
        lines.append(" " * pad + _red(l))
    lines.append("")
    author = "author: DRAK0NN"
    lines.append(" " * max(0, (tw - len(author)) // 2) + _dim(author))
    lines.append("")
    status = f"v{__version__}  |  {n} profile{'s' if n != 1 else ''}  |  vpn: {st_c}"
    lines.append(" " * max(0, (tw - _vislen(status)) // 2) + status)
    lines.append("")

    print("\n".join(lines))


_CMD_HELP = [
    ("list, ls", "list profiles"),
    ("add <url> [-n name]", "add profile (vless/hysteria2)"),
    ("sub <url>", "add subscription"),
    ("sub-update [url]", "refresh subscriptions"),
    ("up [name] [--no-bypass] [--fallback]", "connect"),
    ("down", "disconnect"),
    ("status, st", "show status"),
    ("stats", "show traffic"),
    ("speedtest [--full]", "latency-test all profiles"),
    ("bypass-import <file>", "import Amnezia bypass list"),
    ("bypass-list", "show custom bypass stats"),
    ("bypass-clear", "clear custom bypass list"),
    ("rm <name|index>", "remove profile"),
    ("default <name|index>", "set default"),
    ("emergency-off", "hard stop + clean"),
    ("help, ?", "this help"),
    ("exit, q", "quit"),
]


def _help():
    print()
    for cmd, desc in _CMD_HELP:
        print(f"  {_green(cmd.ljust(28))} {desc}")
    print()


def _err(s):
    print(_red(f"!! {s}"), file=sys.stderr)


def _info(s):
    print(f"{_green('::')} {s}")


def _dispatch(argv):
    from .cli import main
    try:
        return main(argv)
    except SystemExit:
        return 1


def _do_list():
    lines = display.list_lines(color=True)
    if not lines:
        _info("no profiles")
        return
    for line in lines:
        print(line)


def _do_status():
    for line in display.status_lines(color=True, indent="  "):
        print(line)


def _do_stats():
    if not proc.xray_running():
        _err("xray not running")
        return
    up, dn = stats.proxy_traffic()
    print("  " + display.stats_line(up, dn, color=True))


_CMDS = ["list", "ls", "add", "sub", "sub-update", "up", "down", "status",
         "st", "stats", "speedtest", "bypass-import", "bypass-list",
         "bypass-clear", "rm", "default", "emergency-off", "help",
         "exit", "quit", "q"]


def _completer(text, state):
    matches = [c for c in _CMDS if c.startswith(text)]
    return matches[state] if state < len(matches) else None


def _prompt():
    if isatty() and not os.environ.get("NO_COLOR"):
        return "\001\033[1;31m\002drkvl\001\033[0m\002 \001\033[2m\002>\001\033[0m\002 "
    return "drkvl > "


def run() -> int:
    """Run the interactive TUI shell until the user exits; return an exit code."""
    _banner()

    try:
        import readline
        readline.set_completer(_completer)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" ")
    except ImportError:
        pass

    prompt = _prompt()

    while True:
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError:
            parts = raw.split()

        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("exit", "quit", "q"):
            break
        elif cmd in ("help", "?"):
            _help()
        elif cmd in ("list", "ls"):
            _do_list()
        elif cmd in ("status", "st"):
            _do_status()
        elif cmd == "stats":
            _do_stats()
        elif cmd == "speedtest":
            _dispatch(["speedtest"] + args)
        elif cmd == "bypass-import":
            if not args:
                _err("usage: bypass-import <file.json>")
            else:
                _dispatch(["bypass-import"] + args)
        elif cmd == "bypass-list":
            _dispatch(["bypass-list"])
        elif cmd == "bypass-clear":
            _dispatch(["bypass-clear"])
        elif cmd == "add":
            if not args:
                _err("usage: add <vless://... | hysteria2://...> [-n name]")
            else:
                _dispatch(["add"] + args)
        elif cmd == "sub":
            if not args:
                _err("usage: sub <url>")
            else:
                _dispatch(["sub"] + args)
        elif cmd == "sub-update":
            _dispatch(["sub-update"] + args)
        elif cmd == "up":
            _dispatch(["up"] + args)
        elif cmd == "down":
            _dispatch(["down"])
        elif cmd == "rm":
            if not args:
                _err("usage: rm <name|index>")
            else:
                _dispatch(["rm"] + args)
        elif cmd == "default":
            if not args:
                _err("usage: default <name|index>")
            else:
                _dispatch(["default"] + args)
        elif cmd == "emergency-off":
            _dispatch(["emergency-off"])
        else:
            _err(f"unknown: {cmd}")
            print(f"  type {_dim('help')} for commands")

    return 0
