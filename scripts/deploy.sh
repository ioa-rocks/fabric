#!/usr/bin/env bash
# Deploy the fabric binary to running nodes, without root on the far side.
#
# Why not plain scp: the kernel refuses to truncate an executing file
# (ETXTBSY), so copying over a live binary fails. rename() replaces the
# directory entry, not the inode — upload *next to* the target, then mv
# over it; the old daemon keeps running from the orphaned inode until
# bounced. And with no remote sudo there is no `systemctl restart`, but
# the unit runs as the login user with Restart=on-failure: SIGKILLing the
# main PID counts as a failure, and systemd brings it back on the new
# binary (RestartSec=5).
#
# Usage: scripts/deploy.sh <ssh-host> [ssh-host...]
#
# Per host, everything is discovered from the unit itself: binary path and
# PID via `systemctl show` (system unit first, then --user), target arch
# via uname. Cross-builds from the working tree — deploy what you mean to.
set -euo pipefail
cd "$(dirname "$0")/.."

[ $# -ge 1 ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

for host in "$@"; do
  echo "== $host"

  sysctl="systemctl"
  exec_start=$(ssh "$host" "systemctl show fabric -p ExecStart --value 2>/dev/null" || true)
  if [ -z "$exec_start" ]; then
    sysctl="systemctl --user"
    exec_start=$(ssh "$host" "systemctl --user show fabric -p ExecStart --value 2>/dev/null" || true)
  fi
  bin=$(sed -n 's/.*path=\([^ ;]*\).*/\1/p' <<<"$exec_start")
  [ -n "$bin" ] || { echo "   no fabric unit found on $host" >&2; exit 1; }
  oldpid=$(ssh "$host" "$sysctl show fabric -p MainPID --value")

  case $(ssh "$host" uname -m) in
    x86_64)  goarch=amd64 ;;
    aarch64) goarch=arm64 ;;
    armv7l)  goarch=arm ;;
    *)       echo "   unmapped remote arch" >&2; exit 1 ;;
  esac
  out="build/fabric-linux-$goarch"
  GOOS=linux GOARCH=$goarch go build -o "$out" ./cmd/fabric

  # Stream over the ssh connection itself — no scp, so IPv6 literals and
  # jump hosts need no special quoting.
  ssh "$host" "cat > '$bin.next' && chmod 755 '$bin.next' && mv -f '$bin.next' '$bin'" < "$out"
  echo "   binary swapped: $bin ($goarch)"

  if [ "$oldpid" -gt 0 ] 2>/dev/null; then
    ssh "$host" "kill -9 $oldpid"
    newpid=0
    for _ in $(seq 1 20); do
      sleep 1
      newpid=$(ssh "$host" "$sysctl show fabric -p MainPID --value" || echo 0)
      if [ "$newpid" -gt 0 ] 2>/dev/null && [ "$newpid" != "$oldpid" ]; then break; fi
    done
    if ! [ "$newpid" -gt 0 ] 2>/dev/null || [ "$newpid" = "$oldpid" ]; then
      echo "   daemon did not come back — check: journalctl -u fabric" >&2
      exit 1
    fi
    echo "   daemon restarted (pid $oldpid -> $newpid)"
    # health: the control socket answering is the real "it's up"
    ssh "$host" "for i in \$(seq 1 10); do '$bin' status 2>/dev/null | head -1 && exit 0; sleep 1; done; echo 'daemon up but control socket not answering' >&2; exit 1"
  else
    echo "   daemon was not running — start it with: $sysctl start fabric"
  fi
done
