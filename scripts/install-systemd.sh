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
# The system service is sandboxed: the daemon sees an empty, read-only home
# and a read-only system, and can write only its own state directories, the
# folder replicas and placement roots it has declared, and directories
# named with -w. A flaw in the daemon then exposes Fabric's data, not the
# rest of the account (SSH keys, browser profiles, other projects). The
# list comes from the daemon itself (`fabric up -paths`), so re-run this
# script after declaring a folder or root somewhere new.
#
# A sandboxed daemon cannot own FUSE mounts: the mount helper needs a
# privilege the sandbox withholds, and a mount made inside the sandbox is
# not visible outside it. A node with declared mounts therefore needs -m,
# which installs the service with no sandbox at all. The user service is
# never sandboxed: the user manager cannot enforce it.
#
# Usage:
#   sudo ./scripts/install-systemd.sh [-b bin] [-u user] [-s statedir] [-n] [-m] [-w dir]...
#        ./scripts/install-systemd.sh -U [-b bin] [-s statedir] [-n]
#
#   -U  user service (no root)
#   -b  source binary to install (default: ~/.local/bin/fabric, PATH, ./fabric)
#       The service always runs the target user's ~/.local/bin/fabric.
#   -u  user to run as, system mode only (default: $SUDO_USER)
#   -s  state directory (default: the target user's ~/.config/fabric)
#   -n  pass -no-tun to the daemon
#   -m  keep daemon-owned mounts: system service without the sandbox
#   -w  a further directory the sandboxed daemon may write, for a folder
#       replica or placement root that is not declared yet (repeatable)
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

# One path as an item of a systemd path list: quoted, with % doubled so it
# is not read as a specifier. Characters that would need escaping inside the
# quotes, or would split a bind into source and destination, are refused.
#   $1 prefix ("-" = skip the bind when the path is absent)   $2 path
unit_path() {
  case $2 in
    /*) ;;
    *) echo "not an absolute path: $2" >&2; return 1 ;;
  esac
  case $2 in
    *\"*|*\\*|*:*|*$'\n'*)
      echo "cannot name this path in a unit file (quote, backslash, colon or newline): $2" >&2
      return 1 ;;
  esac
  printf '"%s%s"' "$1" "${2//%/%%}"
}

# The unit's sandbox, written from the daemon's own account of what it
# touches (`fabric up -paths` on stdin). Fails, printing nothing to stdout,
# when that account names something a sandboxed daemon cannot serve.
#   $1 service user's home   $2 installed binary   $3... further writable dirs
sandbox_lines() (
  home=$1 bin=$2
  shift 2
  states=() sockets=() optional=() mounts=() legacy=()
  while IFS=$'\t' read -r kind path; do
    case $kind in
      state) states+=("$path") ;;
      socket) sockets+=("$path") ;;
      root|folder) optional+=("$path") ;;
      mount) mounts+=("$path") ;;
      legacy) legacy+=("$path") ;;
      "") ;;
      *) echo "unknown line from 'fabric up -paths': $kind $path" >&2; exit 1 ;;
    esac
  done
  [ "${#states[@]}" -gt 0 ] || { echo "'fabric up -paths' named no state directory" >&2; exit 1; }
  if [ "${#mounts[@]}" -gt 0 ]; then
    {
      echo "this node has daemon-owned mounts, which a sandboxed daemon cannot establish:"
      printf '  %s\n' "${mounts[@]}"
      echo "Remove them (fabric bucket unmount <dir>) and re-run, or re-run with -m to"
      echo "install the service without the sandbox."
    } >&2
    exit 1
  fi
  if [ "${#legacy[@]}" -gt 0 ]; then
    {
      echo "these directories are still at their old place and move at the next daemon start:"
      printf '  %s\n' "${legacy[@]}"
      echo "The move cannot happen inside the sandbox. Start the daemon once without it"
      echo "(re-run with -m), check 'fabric status', then re-run without -m."
    } >&2
    exit 1
  fi
  # A socket outside the state directories is the fallback for a long state
  # path: it lives in the temp directory, which the sandbox makes private.
  for socket in "${sockets[@]}"; do
    inside=0
    for state in "${states[@]}"; do
      case $socket in "$state"/*) inside=1 ;; esac
    done
    if [ "$inside" -eq 0 ]; then
      echo "control socket $socket is outside the state directories (the state path is too long for a socket), so clients could not reach a sandboxed daemon. Use a shorter state path, or -m." >&2
      exit 1
    fi
  done

  lines=(
    "# Sandbox. The daemon sees a read-only system and an empty, read-only home;"
    "# it writes only what is bound below. Generated from 'fabric up -paths':"
    "# re-run the installer after declaring a folder or placement root elsewhere."
    "NoNewPrivileges=true"
    "ProtectSystem=strict"
    "ProtectHome=tmpfs"
  )
  case $home in
    /home/*|/root|/root/*) ;;
    *) item=$(unit_path "" "$home") || exit 1
       lines+=("TemporaryFileSystem=$item:ro") ;;
  esac
  item=$(unit_path "" "$bin") || exit 1
  lines+=("BindReadOnlyPaths=$item")
  for state in "${states[@]}"; do
    item=$(unit_path "" "$state") || exit 1
    lines+=("BindPaths=$item")
  done
  # Declared and requested directories may be absent (an array not mounted):
  # "-" skips the bind, and the daemon then finds the path read-only.
  for directory in "${optional[@]}" "$@"; do
    item=$(unit_path "-" "$directory") || exit 1
    lines+=("BindPaths=$item")
  done
  lines+=(
    "PrivateTmp=true"
    "ProtectKernelTunables=true"
    "ProtectKernelModules=true"
    "ProtectKernelLogs=true"
    "ProtectControlGroups=true"
    "ProtectHostname=true"
    "RestrictSUIDSGID=true"
    "RestrictRealtime=true"
    "RestrictNamespaces=true"
    "LockPersonality=true"
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK"
    "SystemCallArchitectures=native"
  )
  printf '%s\n' "${lines[@]}"
)

# The state directories among `fabric up -paths` lines on stdin.
state_dirs() {
  while IFS=$'\t' read -r kind path; do
    [ "$kind" != state ] || printf '%s\n' "$path"
  done
}

main() {
BIN="" RUN_USER="${SUDO_USER:-}" STATE="" NOTUN="" USERMODE=0 KEEP_MOUNTS=0
WRITABLE=()
while getopts "Ub:u:s:nmw:h" opt; do
  case $opt in
    U) USERMODE=1 ;;
    b) BIN=$OPTARG ;;
    u) RUN_USER=$OPTARG ;;
    s) STATE=$OPTARG ;;
    n) NOTUN=" -no-tun" ;;
    m) KEEP_MOUNTS=1 ;;
    w) WRITABLE+=("$(readlink -m "$OPTARG")") ;;
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

# Decide the sandbox before installing or changing anything: a refusal here
# leaves the binary, the unit and the running service as they were.
SANDBOX="# No sandbox (-m): this node keeps daemon-owned mounts. The daemon can read
# and write whatever its user can."
PATHS=""
if [ "$USERMODE" -eq 0 ] && [ "$KEEP_MOUNTS" -eq 0 ]; then
  # shellcheck disable=SC2086  # NOTUN is one optional flag
  PATHS=$(env -i HOME="$HOME_DIR" PATH=/usr/bin:/bin "$BIN" up -paths -state "$STATE"$NOTUN) || {
    echo "$BIN cannot report the paths it uses ('fabric up -paths'): install a current build, or use -m" >&2
    exit 1
  }
  SANDBOX=$(printf '%s\n' "$PATHS" | sandbox_lines "$HOME_DIR" "$HOME_DIR/.local/bin/fabric" "${WRITABLE[@]}")
fi

# Validate identity/state before installing or changing the service.
if [ "$USERMODE" -eq 1 ]; then
  BIN=$(install_binary "$BIN" "$HOME_DIR")
else
  BIN=$(install_binary "$BIN" "$HOME_DIR" "$RUN_USER")
fi
mkdir -p "$UNIT_DIR"

# A state directory that does not exist yet could not be bound, and the
# daemon could not create it in a read-only home.
printf '%s\n' "$PATHS" | state_dirs | while IFS= read -r directory; do
  [ -d "$directory" ] || runuser -u "$RUN_USER" -- mkdir -p -m 0700 "$directory"
done

if [ "$USERMODE" -eq 1 ]; then
  # Minimal on purpose: the user manager can't grant capabilities or reduce
  # bounding sets, and network-online.target doesn't exist in the user
  # manager — the daemon's own bootstrap-reconnect covers network timing.
  # No sandbox either: where the user manager cannot set up namespaces it
  # ignores those settings without a word, which is worse than not having them.
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
  # The mount helper is setuid root and needs a capability outside this
  # bound, so a node that keeps mounts cannot have the bound either.
  CAP_BOUND="CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
  [ "$KEEP_MOUNTS" -eq 0 ] || CAP_BOUND="# No capability bound (-m): the mount helper needs more than these."
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
$CAP_BOUND
$SANDBOX

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable fabric.service
  systemctl restart fabric.service
  echo "installed $UNIT (user=$RUN_USER, state=$STATE)"
  echo "  logs:    journalctl -u fabric -f"
  echo "  upgrade: replace $BIN, then: sudo systemctl restart fabric"
  if [ "$KEEP_MOUNTS" -eq 1 ]; then
    echo "  sandbox: none (-m)"
  else
    echo "  sandbox: on; the daemon can write only:"
    grep '^BindPaths=' "$UNIT" | sed 's/^BindPaths=/    /'
    echo "  a new folder replica or placement root elsewhere: re-run with -w <dir> first"
  fi
fi

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
