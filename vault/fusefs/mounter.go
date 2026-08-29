package fusefs

import (
	"path/filepath"

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
	return Mount(dir, bucket, daemon.NewClient(m.StatePath), Options{
		Debug:    m.Debug,
		Writable: writable,
		StageDir: filepath.Join(m.StatePath, "mount"),
	})
}
