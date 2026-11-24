package fusefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"ioa.rocks/fabric/vault/daemon"
)

// DaemonMounter implements daemon.Mounter over this package: declared
// mounts are served inside the daemon process, reading and writing through
// the daemon's own control socket — the mount stays one more API consumer
// (ADR 0016: daemon-owned mounts). The composition root wires it in before
// the subsystem runs; this package already imports daemon for the object
// API, so the daemon cannot construct it itself.
type DaemonMounter struct {
	StatePath string // vault state dir: control socket and staging live here
	Debug     bool
}

func (m DaemonMounter) Mount(bucket, dir string, writable bool) (daemon.MountHandle, error) {
	if cannotGainPrivileges() {
		return nil, errSandboxedMount
	}
	return Mount(dir, bucket, daemon.NewClient(m.StatePath), Options{
		Debug:    m.Debug,
		Writable: writable,
		StageDir: filepath.Join(m.StatePath, "mount"),
	})
}

// errSandboxedMount is why a mount cannot be established under the service
// sandbox, said before the mount helper fails with a bare "permission denied".
var errSandboxedMount = errors.New("this daemon runs in a service sandbox and cannot establish mounts: " +
	"the sandbox stops the mount helper from gaining the privilege it needs, and a mount made inside it would not be visible outside. " +
	"Reinstall the service with 'install-systemd.sh -m' (no sandbox), or remove the mount with 'fabric bucket unmount'")

// cannotGainPrivileges reports whether this process is unprivileged and
// barred from gaining privileges through a setuid program (the kernel's
// no_new_privs bit, set by systemd's NoNewPrivileges= and everything that
// implies it). The FUSE mount helper is such a program.
func cannotGainPrivileges() bool {
	if os.Geteuid() == 0 {
		return false
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return noNewPrivs(status)
}

// noNewPrivs reads the NoNewPrivs line of a /proc/<pid>/status file.
func noNewPrivs(status []byte) bool {
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
			return strings.TrimSpace(value) == "1"
		}
	}
	return false
}
