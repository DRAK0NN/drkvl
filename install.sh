#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/DRAK0NN/drkvl"
XRAY_VER="26.5.9"
TUN2SOCKS_VER="2.6.0"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
info()  { printf ':: %s\n' "$*"; }
die()   { red "error: $*"; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "linux only"
[ "$(id -u)" = "0" ] || die "run as root: sudo bash install.sh"

arch=$(uname -m)
case "$arch" in
    x86_64)  xray_arch="64"; t2s_arch="amd64" ;;
    aarch64) xray_arch="arm64-v8a"; t2s_arch="arm64" ;;
    armv7l)  xray_arch="arm32-v7a"; t2s_arch="armv7" ;;
    *)       die "unsupported arch: $arch" ;;
esac

has() { command -v "$1" &>/dev/null; }

detect_pm() {
    if has nix-env;  then echo nix
    elif has pacman; then echo pacman
    elif has apt;    then echo apt
    elif has dnf;    then echo dnf
    elif has zypper; then echo zypper
    elif has apk;    then echo apk
    else echo unknown
    fi
}

BIN_DIR="/usr/local/bin"

install_xray() {
    if has xray; then
        dim "xray already installed: $(xray version | head -1)"
        return
    fi
    info "installing xray $XRAY_VER"
    local tmp=$(mktemp -d)
    local url="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VER}/Xray-linux-${xray_arch}.zip"
    curl -sL "$url" -o "$tmp/xray.zip" || die "failed to download xray"
    unzip -qo "$tmp/xray.zip" xray -d "$tmp" || die "failed to extract xray"
    mkdir -p "$BIN_DIR"
    install -m 755 "$tmp/xray" "$BIN_DIR/xray"
    rm -rf "$tmp"
    green "xray installed to $BIN_DIR/xray"
}

install_tun2socks() {
    if has tun2socks; then
        dim "tun2socks already installed: $(tun2socks -version 2>&1 | head -1 || echo 'ok')"
        return
    fi
    info "installing tun2socks $TUN2SOCKS_VER"
    local tmp=$(mktemp -d)
    local url="https://github.com/xjasonlyu/tun2socks/releases/download/v${TUN2SOCKS_VER}/tun2socks-linux-${t2s_arch}.zip"
    curl -sL "$url" -o "$tmp/t2s.zip" || die "failed to download tun2socks"
    unzip -qo "$tmp/t2s.zip" tun2socks-linux-${t2s_arch} -d "$tmp" || die "failed to extract tun2socks"
    mkdir -p "$BIN_DIR"
    install -m 755 "$tmp/tun2socks-linux-${t2s_arch}" "$BIN_DIR/tun2socks"
    rm -rf "$tmp"
    green "tun2socks installed to $BIN_DIR/tun2socks"
}

install_tun2socks_nix() {
    if has tun2socks; then
        dim "tun2socks already installed"
        return
    fi
    info "installing tun2socks via nix"
    nix-env -iA nixpkgs.tun2socks 2>/dev/null || install_tun2socks
}

install_deps_pm() {
    local pm="$1"
    case "$pm" in
        nix)
            install_xray
            install_tun2socks_nix
            ;;
        pacman)
            has python3 || pacman -S --noconfirm python
            has unzip   || pacman -S --noconfirm unzip
            has ip      || pacman -S --noconfirm iproute2
            has git     || pacman -S --noconfirm git
            install_xray
            install_tun2socks
            ;;
        apt)
            apt-get update -qq
            has python3 || apt-get install -y python3
            has unzip   || apt-get install -y unzip
            has curl    || apt-get install -y curl
            has ip      || apt-get install -y iproute2
            has git     || apt-get install -y git
            install_xray
            install_tun2socks
            ;;
        dnf)
            has python3 || dnf install -y python3
            has unzip   || dnf install -y unzip
            has ip      || dnf install -y iproute
            has git     || dnf install -y git
            install_xray
            install_tun2socks
            ;;
        zypper)
            has python3 || zypper install -y python3
            has unzip   || zypper install -y unzip
            has ip      || zypper install -y iproute2
            has git     || zypper install -y git
            install_xray
            install_tun2socks
            ;;
        apk)
            has python3 || apk add python3
            has unzip   || apk add unzip
            has curl    || apk add curl
            has ip      || apk add iproute2
            has git     || apk add git
            install_xray
            install_tun2socks
            ;;
        *)
            install_xray
            install_tun2socks
            ;;
    esac
}

install_drkvl() {
    info "installing drkvl"

    if [ -d /opt/drkvl ]; then
        info "updating existing installation"
        cd /opt/drkvl
        if [ -d .git ]; then
            git pull --ff-only 2>/dev/null || true
        fi
    else
        if has git; then
            git clone --depth 1 "$REPO" /opt/drkvl
        else
            die "git not found, install git or clone manually"
        fi
    fi

    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/drkvl" << 'WRAPPER'
#!/usr/bin/env bash
cd /opt/drkvl && exec python3 -m drkvl "$@"
WRAPPER
    chmod 755 "$BIN_DIR/drkvl"
    green "drkvl installed to $BIN_DIR/drkvl"
}

check_python() {
    if ! has python3; then
        die "python3 not found"
    fi
    local ver=$(python3 -c 'import sys; print(sys.version_info >= (3,9))' 2>/dev/null)
    [ "$ver" = "True" ] || die "python >= 3.9 required"
}

pm=$(detect_pm)
info "detected package manager: $pm"

install_deps_pm "$pm"
check_python
install_drkvl

has ip || die "iproute2 not found"

echo
green "drkvl installed successfully"
echo
echo "  quick start:"
echo "    drkvl add 'vless://...'"
echo "    sudo drkvl up"
echo "    sudo drkvl down"
echo
dim "  xray:      $(xray version 2>/dev/null | head -1 || echo 'not found')"
dim "  tun2socks: $(tun2socks -version 2>&1 | head -1 || echo 'installed')"
dim "  drkvl:     $BIN_DIR/drkvl"
