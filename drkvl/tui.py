import os
import shlex
import sys
import time

from . import __version__, profile, proc, stats
from .util import isatty, fmt_bytes, fmt_duration


def _c(code, s):
    if not isatty() or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def _red(s): return _c("1;31", s)
def _white(s): return _c("1;37", s)
def _green(s): return _c("32", s)
def _cyan(s): return _c("36", s)
def _yellow(s): return _c("33", s)
def _dim(s): return _c("2", s)
def _orange(s): return _c("38;5;208", s)


_TITLE = [
    r" _____     _____     _    __  __      __   _",
    r"|  __ \   |  __ \   | |  / /  \ \    / /  | |",
    r"| |  | |  | |__) |  | | / /    \ \  / /   | |",
    r"| |  | |  |  _  /   |  <        \ \/ /    | |",
    r"| |__| |  | | \ \   | | \ \      \  /     | |____",
    r"|_____/   |_|  \_\  |_|  \_\      \/      |______|",
]


def _termwidth():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


_ANSI_RE = __import__("re").compile(r"\033\[[^m]*m")


def _vislen(s):
    return len(_ANSI_RE.sub("", s))


def _banner():
    print("\033[2J\033[H", end="")

    n = len(profile.list_all())
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
    ("add <url> [-n name]", "add profile"),
    ("up [name] [--no-bypass]", "connect"),
    ("down", "disconnect"),
    ("status, st", "show status"),
    ("stats", "show traffic"),
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
    items = profile.list_all()
    if not items:
        _info("no profiles")
        return
    default = profile.DEFAULT.read_text().strip() if profile.DEFAULT.exists() else None
    for i, (n, v) in enumerate(items):
        mark = "*" if n == default else " "
        sec = v.security or "none"
        tag = v.name if v.name else ""
        print(f"{mark} {i}  {_cyan(n.ljust(24))} {v.host}:{v.port}  {v.network}/{sec}  {tag}")


def _do_status():
    active = profile.read_json(profile.ACTIVE)
    xr, t2 = proc.xray_running(), proc.tun2socks_running()
    st = "on" if (xr and t2) else ("partial" if (xr or t2) else "off")
    sc = _green(st) if st == "on" else (_yellow(st) if st == "partial" else st)
    print(f"  state:     {sc}")
    print(f"  xray:      {_green('running') if xr else 'stopped'}")
    print(f"  tun2socks: {_green('running') if t2 else 'stopped'}")
    if active:
        up = time.time() - active.get("started", time.time())
        print(f"  profile:   {_cyan(active.get('name', '?'))}")
        print(f"  server:    {active.get('host')}:{active.get('port')}")
        print(f"  uptime:    {fmt_duration(up)}")


def _do_stats():
    if not proc.xray_running():
        _err("xray not running")
        return
    up, dn = stats.proxy_traffic()
    print(f"  {_yellow('↑')} {fmt_bytes(up):>8}    {_yellow('↓')} {fmt_bytes(dn):>8}")


_CMDS = ["list", "ls", "add", "up", "down", "status", "st", "stats",
         "rm", "default", "emergency-off", "help", "exit", "quit", "q"]


def _completer(text, state):
    matches = [c for c in _CMDS if c.startswith(text)]
    return matches[state] if state < len(matches) else None


def _prompt():
    if isatty() and not os.environ.get("NO_COLOR"):
        return "\001\033[1;31m\002drkvl\001\033[0m\002 \001\033[2m\002>\001\033[0m\002 "
    return "drkvl > "


def run() -> int:
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
        elif cmd == "add":
            if not args:
                _err("usage: add <vless://...> [-n name]")
            else:
                _dispatch(["add"] + args)
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
