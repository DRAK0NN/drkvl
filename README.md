# drkvl
![License](https://img.shields.io/github/license/DRAK0NN/drkvl)
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

          v0.2.1  |  2 profiles  |  vpn: off

  list, ls                     list profiles
  add <url> [-n name]          add profile
  up [name] [--no-bypass]      connect
  down                         disconnect
  status, st                   show status
  stats                        show traffic
  rm <name|index>              remove profile
  default <name|index>         set default
  emergency-off                hard stop + clean
  help, ?                      this help
  exit, q                      quit
```

## features

- VLESS + Reality + xhttp (post-quantum ML-DSA-65 supported)
- full TUN routing via `tun2socks` + `xray` socks5
- interactive TUI with tab completion
- geo-bypass: RU sites/IPs go direct (geosite + geoip)
- DNS over TCP through xray (no UDP leaks)
- split routing with fwmark + connmark (NixOS rpfilter compatible)

## requires

| dep | version |
|-----|---------|
| xray | >= 26.5 (xhttp support) |
| tun2socks | any |
| iproute2 | any |
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
sudo drkvl down
sudo drkvl emergency-off   # hard cleanup
```

drkvl honours `SUDO_USER` — profiles stay under the invoking user's `~/.config/drkvl/`.

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
- ports `1080` (socks) and `10085` (xray api) are hardcoded
- TUN interface `drkvl0` uses `10.10.0.0/16`
- DNS forced to `1.1.1.1` / `8.8.8.8`; original resolv.conf restored on down
- if anything breaks: `sudo drkvl emergency-off`

## layout

```
drkvl/
  cli.py        argparse entry + commands
  tui.py        interactive TUI (readline, colors)
  link.py       vless:// URI parser
  config.py     xray JSON config generator
  profile.py    on-disk state (~/.config/drkvl/)
  proc.py       xray / tun2socks lifecycle
  tun.py        TUN device + routing + iptables
  stats.py      xray gRPC stats API
  geo.py        geosite/geoip asset manager
  clash.py      clash/mihomo conflict handler
  util.py       misc helpers
drkvl-run       standalone entry point
pyproject.toml  package metadata
```
