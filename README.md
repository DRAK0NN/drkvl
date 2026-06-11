## drkvl

cli for managing a vless vpn on linux. tun mode only — all
system traffic goes through the vpn.

routes the kernel through `tun2socks(8)` into an `xray` socks5
inbound. supports xhttp + reality (incl. ml-dsa-65 / `pqv`).

### requires

- `xray` (https://github.com/XTLS/Xray-core)
- `tun2socks` (https://github.com/xjasonlyu/tun2socks)
- `iproute2` (`ip`)
- python ≥ 3.9, stdlib only

### install

one-liner (any distro):

    sudo bash <(curl -sL https://raw.githubusercontent.com/DRAK0NN/drkvl/main/install.sh)

run from source:

    git clone https://github.com/DRAK0NN/drkvl /opt/drkvl
    python3 -m drkvl ...

### nixos

`pip install` doesn't work on nixos (read-only nix store). use the
install script or run from source. for deps:

    nix-env -iA nixos.tun2socks

xray from nixos repos is often too old (no xhttp support). install
v26+ manually:

    curl -sL https://github.com/XTLS/Xray-core/releases/download/v26.5.9/Xray-linux-64.zip -o /tmp/xray.zip
    unzip /tmp/xray.zip xray -d ~/.local/bin && chmod +x ~/.local/bin/xray

make sure `~/.local/bin` is in your PATH (add to `~/.bashrc`):

    export PATH="$HOME/.local/bin:$PATH"

when running `sudo drkvl up`, pass the PATH:

    sudo env PATH="$HOME/.local/bin:$PATH" python3 -m drkvl up

### use

    drkvl add 'vless://...#name'
    drkvl add 'vless://...' -n work
    drkvl list
    drkvl default work
    drkvl rm work
    drkvl status
    drkvl stats
    drkvl stats -f

    sudo drkvl up              # default profile
    sudo drkvl up work         # named profile
    sudo drkvl down
    sudo drkvl emergency-off   # hard stop, clean tun, restore routes

`add`, `list`, `rm`, `default`, `status`, `stats` run as a normal
user. `up`, `down` and `emergency-off` need root for `ip(8)`,
`tun2socks(8)` and `/etc/resolv.conf`. drkvl honours `SUDO_USER`,
so profiles stay under the invoking user's `~/.config/drkvl/`.

state lives in `~/.config/drkvl/`:

    profiles/   parsed vless profiles
    default     name of the default profile
    active.json current session (pid, profile, start time)
    backup_routes.json  original routes + resolv.conf
    xray_config.json    generated xray config

### vless link

supported query params:

    type           tcp, ws, grpc, xhttp, httpupgrade
    security       reality, tls, none
    encryption     usually none
    flow           e.g. xtls-rprx-vision

    path, mode, extra, host    xhttp / ws
    serviceName, authority     grpc

    sni, fp, alpn              tls
    pbk, sid, spx, pqv         reality

fragment after `#` is the profile name.

### caveats

- single profile up at a time. ports `1080` (socks) and `10085`
  (xray api) are fixed.
- `10.10.0.0/16` is used for the tun interface (`drkvl0`).
- dns is forced to `1.1.1.1` / `8.8.8.8` to prevent leaks; the
  original `/etc/resolv.conf` is saved and restored on down.
- if anything goes wrong: `drkvl emergency-off`.

### layout

    drkvl/
      link.py     vless:// parser
      config.py   xray json generator
      profile.py  on-disk state
      proc.py     xray / tun2socks lifecycle
      tun.py      tun + routes + sudo prompt
      stats.py    xray stats api
      cli.py      argparse entry
      util.py     misc
