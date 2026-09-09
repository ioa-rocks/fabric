#!/usr/bin/env bash
# Install the fabric daemon as a systemd service.
#
# Two modes, chosen by trust boundary (not by whether you have root):
#
#   System service (default, needs root) — machines that are yours alone.
#   Starts at boot, no login needed; CAP_NET_ADMIN (TUN device) and
#   CAP_NET_BIND_SERVICE (.fabric DNS on :53) are granted by systemd itself
#   via AmbientCapabilities — no setcap on the binary, so upgrades are just
#   "replace binary, systemctl restart fabric".
#
#   User service (-U, no root anywhere) — machines other people also use.
#   Unit goes to ~/.config/systemd/user/, state stays in $HOME, zero root
#   footprint; runs while you're logged in (loginctl enable-linger to keep
#   it up, where allowed). Deliberately no TUN / port-53 DNS: a TUN device
#   is host-wide — bridging the overlay on a shared box would give every
#   user on it an IP route into your private network. The daemon runs as a
#   control-plane member; per-user data plane arrives with mode B. Don't
#   setcap the binary on a shared machine to force TUN on.
#
# Usage:
#   sudo ./scripts/install-systemd.sh [-b bin] [-u user] [-s statedir] [-n]
#        ./scripts/install-systemd.sh -U [-b bin] [-s statedir] [-n]
#
#   -U  user service (no root)
#   -b  source binary to install (default: ~/.local/bin/fabric, PATH, ./fabric)
#       The service always runs the target user's ~/.local/bin/fabric.
#   -u  user to run as, system mode only (default: $SUDO_USER)
#   -s  state directory (default: the target user's ~/.config/fabric)
#   -n  pass -no-tun to the daemon
set -euo pipefail

# Copy a build into the canonical per-user location. Kept separate from service
# setup so installation/migration can be tested without touching systemd.
install_binary() (
  source_bin=$(readlink -f "$1") || exit 1
  target_home=$2
  owner=${3:-}
  target_bin=$target_home/.local/bin/fabric
  [ -x "$source_bin" ] || { echo "fabric binary not executable: $source_bin" >&2; exit 1; }
  if [ -n "$owner" ]; then
    install -d -o "$owner" "$target_home/.local" "$target_home/.local/bin" || exit 1
  else
    install -d "$target_home/.local/bin" || exit 1
  fi
  if [ "$source_bin" != "$(readlink -f "$target_bin")" ] || [ -L "$target_bin" ]; then
    staged=$(mktemp "$target_home/.local/bin/.fabric.XXXXXX") || exit 1
    trap 'rm -f "$staged"' EXIT
    if [ -n "$owner" ]; then
      install -m 0755 -o "$owner" "$source_bin" "$staged" || exit 1
    else
      install -m 0755 "$source_bin" "$staged" || exit 1
    fi
    mv -f "$staged" "$target_bin" || exit 1
  fi
  printf '%s\n' "$target_bin"
)

main() {
BIN="" RUN_USER="${SUDO_USER:-}" STATE="" NOTUN="" USERMODE=0
while getopts "Ub:u:s:nh" opt; do
  case $opt in
    U) USERMODE=1 ;;
    b) BIN=$OPTARG ;;
    u) RUN_USER=$OPTARG ;;
    s) STATE=$OPTARG ;;
    n) NOTUN=" -no-tun" ;;
    h|*) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

if [ "$USERMODE" -eq 1 ]; then
  [ "$(id -u)" -ne 0 ] || { echo "-U installs for the calling user — run without sudo" >&2; exit 1; }
  RUN_USER=$USER
  UNIT_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
  HOME_DIR=$HOME
else
  [ "$(id -u)" -eq 0 ] || { echo "needs root: sudo $0 ... (or -U for a user service)" >&2; exit 1; }
  [ -n "$RUN_USER" ] || { echo "-u <user> required (no \$SUDO_USER in env)" >&2; exit 1; }
  id "$RUN_USER" >/dev/null
  UNIT_DIR=/etc/systemd/system
  HOME_DIR=$(getent passwd "$RUN_USER" | cut -d: -f6)
fi
UNIT=$UNIT_DIR/fabric.service

if [ -z "$BIN" ]; then
  if [ -x "$HOME_DIR/.local/bin/fabric" ]; then
    BIN=$HOME_DIR/.local/bin/fabric
  else
    BIN=$(command -v fabric || true)
    [ -n "$BIN" ] || BIN=./fabric
  fi
fi
BIN=$(readlink -f "$BIN")
[ -x "$BIN" ] || { echo "fabric binary not found/executable: $BIN" >&2; exit 1; }

[ -n "$STATE" ] || STATE=$HOME_DIR/.config/fabric
[ -f "$STATE/config.json" ] || {
  echo "state dir $STATE is not initialized — run 'fabric init' or 'fabric join' as $RUN_USER first" >&2
  exit 1
}

# Validate identity/state before installing or changing the service.
if [ "$USERMODE" -eq 1 ]; then
  BIN=$(install_binary "$BIN" "$HOME_DIR")
else
  BIN=$(install_binary "$BIN" "$HOME_DIR" "$RUN_USER")
fi
mkdir -p "$UNIT_DIR"

if [ "$USERMODE" -eq 1 ]; then
  # Minimal on purpose: the user manager can't grant capabilities or reduce
  # bounding sets, and network-online.target doesn't exist in the user
  # manager — the daemon's own bootstrap-reconnect covers network timing.
  cat > "$UNIT" <<EOF
[Unit]
Description=fabric mesh daemon (user)

[Service]
Type=simple
ExecStart="$BIN" up -state "$STATE"$NOTUN
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable fabric.service
  systemctl --user restart fabric.service
  echo "installed $UNIT (state=$STATE)"
  echo "  logs:    journalctl --user -u fabric -f"
  echo "  upgrade: replace $BIN, then: systemctl --user restart fabric"
  echo "  survive logout (if allowed): loginctl enable-linger $USER"
  echo "  note: no TUN / .fabric DNS without capabilities — full member otherwise"
else
  cat > "$UNIT" <<EOF
[Unit]
Description=fabric mesh daemon
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$RUN_USER
ExecStart="$BIN" up -state "$STATE"$NOTUN
Restart=on-failure
RestartSec=5

# TUN device + port-53 DNS without root: pid 1 grants the caps, the binary
# stays uncapped (upgrades = replace binary + restart, no setcap).
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable fabric.service
  systemctl restart fabric.service
  echo "installed $UNIT (user=$RUN_USER, state=$STATE)"
  echo "  logs:    journalctl -u fabric -f"
  echo "  upgrade: replace $BIN, then: sudo systemctl restart fabric"
fi

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
