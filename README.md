# drkvl
![License](https://img.shields.io/badge/license-GPL--3.0-orange)
![Python](https://img.shields.io/badge/python-3.9+-blue)
![Platform](https://img.shields.io/badge/platform-linux-green)

VLESS VPN client for Linux. TUN mode — all system traffic through VPN.

## screenshot

```
 _____     _____     _    __  __      __   _
|  __ \   |  __ \   | |  / /  \ \    / /  | |
| |  | |  | |__) |  | | / /    \ \  / /   | |
| |  | |  |  _  /   |  <        \ \/ /    | |
| |__| |  | | \ \   | | \ \      \  /     | |____
|_____/   |_|  \_\  |_|  \_\      \/      |______|

                    author: DRAK0NN

          v1.0.0  |  2 profiles  |  vpn: off

  list, ls                            list profiles
  add <url> [-n name]                 add profile
  sub <url>                           add subscription
  sub-update [url]                    refresh subscriptions
  up [name] [--no-bypass] [--fallback]  connect
  down                                disconnect
  status, st                          show status
  stats                               show traffic
  speedtest                           latency-test all profiles
  rm <name|index>                     remove profile
  default <name|index>                set default
  emergency-off                       hard stop + clean
  help, ?                             this help
  exit, q                             quit
```

## features

- VLESS + Reality + xhttp (post-quantum ML-DSA-65 supported)
- full TUN routing via `tun2socks` + `xray` socks5
- **subscriptions**: import a base64 link list, refresh in place
- **speedtest**: parallel latency test of every profile
- **`--fallback`**: speed-test all profiles, connect to the fastest that responds
- geo-bypass: RU sites/IPs go direct (geosite + geoip)
- kill-switch: IPv6 egress blocked while up + fail-closed routing (traffic stops, never leaks, if the tunnel drops)
- DNS over TCP through xray (no UDP leaks); resolv.conf saved + restored
- split routing with fwmark + connmark (NixOS rpfilter compatible)
- interactive TUI with tab completion
- stdlib only — no third-party deps; 210 unit tests

## requires

| dep | version |
|-----|---------|
| xray | >= 26.5 (xhttp support) |
| tun2socks | any |
| iproute2 | any |
| curl | any (subscriptions / speedtest) |
| python | >= 3.9, stdlib only |

## install

### one-liner (any distro)

```sh
sudo bash <(curl -sL https://raw.githubusercontent.com/DRAK0NN/drkvl/main/install.sh)
```

Installs xray, tun2socks, iproute2, and drkvl to `/usr/local/bin`.

### NixOS

nixpkgs xray is too old (no xhttp). Install deps + xray binary manually:

```sh
nix-env -iA nixpkgs.python3 nixpkgs.tun2socks nixpkgs.unzip nixpkgs.curl
mkdir -p ~/.local/bin
curl -sL https://github.com/XTLS/Xray-core/releases/download/v26.5.9/Xray-linux-64.zip -o /tmp/xray.zip
unzip /tmp/xray.zip xray -d ~/.local/bin && chmod +x ~/.local/bin/xray
export PATH="$HOME/.local/bin:$PATH"  # add to ~/.bashrc
```

Then clone and run:

```sh
sudo mkdir -p /opt
sudo git clone https://github.com/DRAK0NN/drkvl /opt/drkvl
cd /opt/drkvl && python3 -m drkvl
```

### pip

```sh
pip install --user .
```

## usage

### interactive (TUI)

```sh
drkvl          # launches TUI if on a tty
```

### CLI

```sh
drkvl add 'vless://uuid@host:443?type=xhttp&security=reality&...' -n myserver
drkvl list
drkvl default myserver
drkvl status
drkvl stats -f
```

`up`/`down`/`emergency-off` need root:

```sh
sudo drkvl up              # connect default profile
sudo drkvl up myserver     # connect named profile
sudo drkvl up --no-bypass  # all traffic via VPN (no geo-bypass)
sudo drkvl up --fallback   # speed-test all, connect to the fastest that responds
sudo drkvl down
sudo drkvl emergency-off   # hard cleanup
```

drkvl honours `SUDO_USER` — profiles stay under the invoking user's `~/.config/drkvl/`.

## subscriptions

Import a subscription URL (a base64-encoded, newline-separated link list):

```sh
drkvl sub https://example.com/sub      # import its vless:// profiles as sub-0, sub-1, ...
drkvl sub-update                       # re-fetch every saved subscription, replace its profiles
drkvl sub-update https://example.com/sub   # update just that one
```

Non-vless links (`vmess` / `trojan` / `ss`) are skipped with a warning. http/https
only; the body is capped at 4 MiB. URLs are remembered in
`~/.config/drkvl/subscriptions.json`; a failed refresh keeps the old profiles.

## speedtest

Latency-test every profile in parallel (no root, no connection):

```sh
drkvl speedtest
```

Spins a throwaway xray per profile on its own socks port (`1090+`), measures the
round-trip through the proxy with curl, tears it down, and prints a table sorted
by latency (`profile  server  port  latency  status`). `up --fallback` reuses the
same test and connects to the fastest responder, falling back to the next if it fails.

## vless link

Supported `vless://` query params:

```
type           tcp, ws, grpc, xhttp, httpupgrade
security       reality, tls, none
encryption     none
flow           xtls-rprx-vision

path, mode, extra, host    xhttp / ws
serviceName, authority     grpc

sni, fp, alpn              tls
pbk, sid, spx, pqv         reality
```

Fragment `#name` sets the profile name.

## caveats

- one connection at a time
- ports `1080` (socks) and `10085` (xray api) are hardcoded; speedtest uses `1090+`
- TUN interface `drkvl0` uses `10.10.0.0/16`
- DNS forced to `1.1.1.1` / `8.8.8.8`; original resolv.conf restored on down
- IPv6 egress is blocked while connected and re-enabled on down
- if anything breaks: `sudo drkvl emergency-off`

## layout

```
drkvl/
  cli.py        argparse entry + commands
  tui.py        interactive TUI (readline, colors)
  display.py    shared list/status/stats/speedtest rendering
  link.py       vless:// URI parser
  config.py     xray JSON config generator
  sub.py        subscription fetch / base64 decode / import
  speed.py      parallel profile speed-test (threaded)
  paths.py      filesystem locations
  ownership.py  sudo-aware chown / permissions
  storage.py    profile + JSON persistence
  state.py      default profile + active session
  profile.py    back-compat facade over storage/state/ownership
  proc.py       xray / tun2socks lifecycle
  tun.py        TUN device + routing + iptables + IPv6 block
  stats.py      xray stats API
  geo.py        geosite/geoip asset manager
  clash.py      clash/mihomo conflict handler
  util.py       misc helpers
pyproject.toml  package metadata
tests/          210 unit tests (no root / no network needed)
```
