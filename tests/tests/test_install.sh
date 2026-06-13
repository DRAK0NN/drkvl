#!/usr/bin/env bash
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS=()

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()  { printf ':: %s\n' "$*"; }

record() {
    local name="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        RESULTS+=("PASS  $name")
        green "PASS  $name"
    else
        RESULTS+=("FAIL  $name")
        red  "FAIL  $name"
    fi
}

# ---------------------------------------------------------------
# Test 1 — Ubuntu 22.04: README "one-liner" section
#   sudo bash <(curl -sL .../install.sh)
#   then: drkvl list
# ---------------------------------------------------------------
test_ubuntu() {
    info "Test 1: Ubuntu 22.04 — README one-liner install"

    docker run --rm \
        -v "$REPO_DIR/install.sh":/tmp/install.sh:ro \
        ubuntu:22.04 \
        bash -c '
set -e

# README says: sudo bash <(curl -sL .../install.sh)
# we mount local install.sh instead of curl to test current code
bash /tmp/install.sh

echo "--- checks ---"
which drkvl     || { echo "FAIL: drkvl not in PATH";   exit 1; }
which xray      || { echo "FAIL: xray not in PATH";    exit 1; }
which tun2socks || { echo "FAIL: tun2socks not in PATH"; exit 1; }
drkvl list      || { echo "FAIL: drkvl list failed";    exit 1; }
echo "--- all checks passed ---"
'
    return $?
}

# ---------------------------------------------------------------
# Test 2 — NixOS: README "NixOS" section verbatim
#   nix-env -iA nixpkgs.python3 nixpkgs.tun2socks nixpkgs.unzip nixpkgs.curl
#   download xray binary to ~/.local/bin
#   git clone ... && python3 -m drkvl
# ---------------------------------------------------------------
test_nix() {
    info "Test 2: NixOS — README NixOS install"

    docker run --rm \
        -v "$REPO_DIR":/repo:ro \
        nixos/nix \
        bash -c '
set -e

# step 1: README NixOS deps
nix-env -iA nixpkgs.python3 nixpkgs.tun2socks nixpkgs.unzip nixpkgs.curl

# step 2: README xray binary
mkdir -p ~/.local/bin
curl -sL https://github.com/XTLS/Xray-core/releases/download/v26.5.9/Xray-linux-64.zip -o /tmp/xray.zip
unzip /tmp/xray.zip xray -d ~/.local/bin && chmod +x ~/.local/bin/xray
export PATH="$HOME/.local/bin:$PATH"

# step 3: README clone + run (use local repo instead of github)
mkdir -p /opt
cp -r /repo /opt/drkvl
cd /opt/drkvl

echo "--- checks ---"
which python3    || { echo "FAIL: python3 not found";    exit 1; }
which tun2socks  || { echo "FAIL: tun2socks not found";  exit 1; }
which xray       || { echo "FAIL: xray not found";       exit 1; }
python3 -m drkvl list || { echo "FAIL: drkvl list failed"; exit 1; }
echo "--- all checks passed ---"
'
    return $?
}

# ---------------------------------------------------------------
info "pulling images..."
docker pull -q ubuntu:22.04
docker pull -q nixos/nix

test_ubuntu; record "Ubuntu 22.04" $?
echo
test_nix;    record "NixOS/nix"    $?

echo
echo "=============================="
echo " Results"
echo "=============================="
for r in "${RESULTS[@]}"; do
    case "$r" in
        PASS*) green "  $r" ;;
        *)     red   "  $r" ;;
    esac
done
echo

failed=0
for r in "${RESULTS[@]}"; do
    [[ "$r" == FAIL* ]] && failed=1
done
exit $failed
