// Daemon-owned mounts (ADR 0016): a mount is declared state, not a
// foreground process. Declarations persist beside subscriptions; the
// daemon establishes them at startup, re-establishes them when they drop,
// and releases them at shutdown. The CLI only edits the declaration.
package daemon

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"syscall"
	"time"

	"ioa.rocks/fabric/vault/circle"
)

// MountReconcileInterval is how often declared-but-dead mounts are retried.
const MountReconcileInterval = 30 * time.Second

// Mounter establishes one FUSE mount on the daemon's behalf. The fusefs
// implementation lives outside this package (fusefs imports the object-API
// types from here), so the composition root wires one in before Run; a
// daemon without a Mounter refuses mount declarations.
type Mounter interface {
	Mount(bucket, dir string, writable bool) (MountHandle, error)
}

// MountHandle is a live mount. *fuse.Server satisfies it.
type MountHandle interface {
	Unmount() error
	Wait()
}

// MountInfo is the wire form of one declared mount.
type MountInfo struct {
	Dir     string `json:"dir"`
	Bucket  string `json:"bucket"` // bucket ID
	Name    string `json:"name,omitempty"`
	Write   bool   `json:"write,omitempty"`
	Mounted bool   `json:"mounted"`
	Error   string `json:"error,omitempty"` // last failed establish attempt
}

type liveMount struct {
	handle MountHandle
	decl   circle.MountDecl
	gen    uint64 // guards the Wait watcher against a remount at the same dir
}

// mountLoop establishes the declared mounts and keeps them established
// until ctx ends. Runs only when a Mounter is wired.
func (d *Daemon) mountLoop() {
	d.reconcileMounts()
	t := time.NewTicker(MountReconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			d.reconcileMounts()
		case <-d.ctx.Done():
			return
		}
	}
}

// reconcileMounts establishes every declared mount that is not live. A
// mount that dropped without RemoveMount — an external fusermount -u, a
// crashed previous daemon — comes back: the declaration is the intent, and
// `fabric vault unmount` is how intent changes.
func (d *Daemon) reconcileMounts() {
	decls, err := d.Circle.Mounts()
	if err != nil {
		log.Printf("vault mounts: reading declarations: %v", err)
		return
	}
	for dir, decl := range decls {
		d.mountMu.Lock()
		_, live := d.liveMounts[dir]
		d.mountMu.Unlock()
		if live {
			continue
		}
		if err := d.establishMount(dir, decl); err != nil {
			d.setMountErr(dir, err)
			log.Printf("vault mounts: %s: %v (will retry)", dir, err)
		}
	}
}

// establishMount performs one mount attempt and registers the watcher that
// clears the live entry when the kernel releases the mount.
func (d *Daemon) establishMount(dir string, decl circle.MountDecl) error {
	if d.Mounter == nil {
		return fmt.Errorf("this daemon has no mounter wired")
	}
	// A previous daemon that died uncleanly leaves a disconnected FUSE
	// mount here; detach it before mounting over it. Only ENOTCONN — an
	// unrelated healthy mount at the declared dir is the operator's to
	// resolve, not ours to unmount.
	if _, err := os.Stat(dir); err != nil && isNotConn(err) {
		_ = LazyUnmount(dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	h, err := d.Mounter.Mount(decl.Bucket, dir, decl.Write)
	if err != nil {
		return err
	}
	d.mountMu.Lock()
	d.mountGen++
	gen := d.mountGen
	d.liveMounts[dir] = &liveMount{handle: h, decl: decl, gen: gen}
	delete(d.mountErrs, dir)
	d.mountMu.Unlock()
	go func() {
		h.Wait()
		d.mountMu.Lock()
		if cur, ok := d.liveMounts[dir]; ok && cur.gen == gen {
			delete(d.liveMounts, dir)
		}
		d.mountMu.Unlock()
	}()
	log.Printf("vault mounts: bucket %.16s mounted at %s (write=%v)", decl.Bucket, dir, decl.Write)
	return nil
}

// releaseMount unmounts dir if live. Declarations are the caller's business.
func (d *Daemon) releaseMount(dir string) error {
	d.mountMu.Lock()
	m, ok := d.liveMounts[dir]
	delete(d.liveMounts, dir)
	delete(d.mountErrs, dir)
	d.mountMu.Unlock()
	if !ok {
		return nil
	}
	if err := m.handle.Unmount(); err != nil {
		// EBUSY — most commonly a shell sitting inside the mount. Detach
		// lazily: the kernel finishes when the last user leaves.
		if lazyErr := LazyUnmount(dir); lazyErr != nil {
			return fmt.Errorf("unmount: %w; lazy detach: %v", err, lazyErr)
		}
	}
	return nil
}

// teardownMounts releases every live mount. Shutdown calls it while the
// control socket still serves: a writable mount flushing staged content on
// unmount publishes through that socket.
func (d *Daemon) teardownMounts() {
	d.mountMu.Lock()
	dirs := make([]string, 0, len(d.liveMounts))
	for dir := range d.liveMounts {
		dirs = append(dirs, dir)
	}
	d.mountMu.Unlock()
	for _, dir := range dirs {
		if err := d.releaseMount(dir); err != nil {
			log.Printf("vault mounts: releasing %s: %v", dir, err)
		}
	}
}

func (d *Daemon) setMountErr(dir string, err error) {
	d.mountMu.Lock()
	d.mountErrs[dir] = err.Error()
	d.mountMu.Unlock()
}

// mountInfos merges declarations with live state for status and listings.
func (d *Daemon) mountInfos() ([]MountInfo, error) {
	decls, err := d.Circle.Mounts()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	if buckets, err := d.Circle.Buckets(); err == nil {
		for _, b := range buckets {
			if id, err := b.ID(); err == nil {
				names[id] = b.Genesis.Name
			}
		}
	}
	d.mountMu.Lock()
	defer d.mountMu.Unlock()
	out := make([]MountInfo, 0, len(decls))
	for dir, decl := range decls {
		_, live := d.liveMounts[dir]
		out = append(out, MountInfo{
			Dir: dir, Bucket: decl.Bucket, Name: names[decl.Bucket],
			Write: decl.Write, Mounted: live, Error: d.mountErrs[dir],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

func isNotConn(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOTCONN
	}
	return false
}

// LazyUnmount detaches a FUSE mountpoint via the fusermount helper — the
// fallback for EBUSY and for disconnected mounts left by an unclean
// shutdown. The helper is needed because an unprivileged mount owner
// cannot call umount(2) directly.
func LazyUnmount(mountpoint string) error {
	for _, name := range []string{"fusermount3", "fusermount"} {
		bin, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		return exec.Command(bin, "-uz", mountpoint).Run()
	}
	return fmt.Errorf("neither fusermount3 nor fusermount is installed")
}
