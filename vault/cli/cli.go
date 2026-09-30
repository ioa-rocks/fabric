// Package cli is the Vault command group ("fabric vault <command> [flags]") — the
// CLI over the object-store API. Data commands work against a running
// daemon's control socket when there is one (the daemon owns the store
// while it runs) and fall back to opening the state directly — same
// operations either way (bucket-model memo §2: the API is the product;
// this is surface #1).
//
// It is a package, not a main, so the one fabric binary can carry it
// (ADR 0013): cmd/fabric dispatches here on `fabric vault …`.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/fusefs"

	"golang.org/x/term"
)

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(rest)
	case "status":
		err = cmdStatus(rest)
	case "buckets":
		err = cmdBuckets(rest)
	case "bucket":
		err = cmdBucket(rest)
	case "put":
		err = cmdPut(rest)
	case "ls":
		err = cmdLs(rest)
	case "tag":
		err = cmdTag(rest)
	case "get":
		err = cmdGet(rest)
	case "rm":
		err = cmdRm(rest)
	case "sub":
		err = cmdSub(rest)
	case "project":
		err = cmdProject(rest)
	case "mount":
		err = cmdMount(rest)
	case "unmount":
		err = cmdUnmount(rest)
	case "mounts":
		err = cmdMounts(rest)
	case "policy":
		err = cmdPolicy(rest)
	case "trash":
		err = cmdTrash(rest)
	case "restore":
		err = cmdRestore(rest)
	case "conflicts":
		err = cmdConflicts(rest)
	case "resolve":
		err = cmdResolve(rest)
	case "held":
		err = cmdHeld(rest)
	default:
		fmt.Fprintf(os.Stderr, "vault: unknown command %q\n\n", cmd)
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: fabric vault <command> [flags]

The data surface of the node. The node daemon itself is 'fabric up' —
it activates the vault subsystem when circle state exists (ADR 0013);
mesh membership is 'fabric join'. Data commands go through the running
daemon's control socket, or open the state directly when none runs.

  init     create a circle on this device (-name required)
  status   show daemon state: circle, mesh, vault peers, mounts
  bucket   bucket create <name> — mint a bucket (signs; needs passphrase)
  buckets  list buckets
  put      put <bucket> <file...> [-tag t1,t2] — add objects
  ls       ls <bucket> [-tag t1,t2] — list objects (tag intersection)
  tag      tag <bucket> <object-ref> [+tag ...] [-tag ...]
  get      get <bucket> <object-ref> [-o file] — read content
  rm       rm <bucket> <object-ref> — tombstone an object
  sub      sub <bucket> [full|cache|none] — this device's placement commitment
  project  project <bucket> <dir> — materialize a read-only directory view
  mount    mount <bucket> <dir> [-write] — declare a mount; the daemon serves
           it from now on, across restarts, until 'unmount'
  unmount  unmount <dir> — remove a mount declaration and release the mount
  mounts   list declared mounts and whether each is live
  policy   policy <bucket> [set key=value ...] — show or sign a policy revision
           (copies trash_days ignore symlinks nested_repos hold_min_count hold_min_percent)
  trash    trash <bucket> — list tombstoned objects
  restore  restore <bucket> <object-ref> — revive a tombstoned object
  conflicts  conflicts <bucket> — list concurrent edits kept as conflict copies
  resolve  resolve <bucket> <object-ref> — settle a conflict for the kept version
  held     held <bucket> [accept|reject] — deletions parked for confirmation

Every command accepts -state <dir> (default `+circle.DefaultPath()+`),
before or after positional arguments. Signing commands read
$VAULT_PASSPHRASE or prompt.
`)
}

// parse runs fs over args accepting flags anywhere, not only before the
// first positional — the usage lines advertise trailing flags and Go's
// parser alone stops at the first positional. Returns the positionals
// in order. After limit positionals (limit >= 0) the remainder is
// returned verbatim, so modifier syntax like "+tag"/"-tag" survives;
// limit < 0 means flags are recognized everywhere. A literal "--" ends
// flag parsing for good.
func parse(fs *flag.FlagSet, args []string, limit int) []string {
	var pos []string
	for len(args) > 0 {
		if args[0] == "--" {
			pos = append(pos, args[1:]...)
			break
		}
		fs.Parse(args)
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
		if limit >= 0 && len(pos) == limit {
			pos = append(pos, args...)
			break
		}
	}
	return pos
}

func stateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", circle.DefaultPath(), "state directory")
}

func passphrase() (string, error) {
	if p := os.Getenv("VAULT_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no terminal for passphrase prompt; set VAULT_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, "circle user-key passphrase: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	statePath := stateFlag(fs)
	name := fs.String("name", "", "circle owner label (required)")
	parse(fs, args, -1)
	if *name == "" {
		return fmt.Errorf("init: -name is required")
	}
	pass, err := passphrase()
	if err != nil {
		return err
	}
	c, err := circle.Init(*statePath, *name, pass)
	if err != nil {
		return err
	}
	fmt.Printf("circle created: %s\n", c.Config.DID)
	fmt.Printf("user-key container: %s — back it up\n", c.Path+"/user.key.age")
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statePath := stateFlag(fs)
	parse(fs, args, -1)
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("no daemon on %s (the node daemon is 'fabric up')", daemon.SocketPath(*statePath))
	}
	s, err := cl.Status()
	if err != nil {
		return err
	}
	fmt.Printf("circle %q  %s\n", s.Name, s.Circle)
	fmt.Printf("daemon %s, %d bucket(s)\n", s.Version, s.Buckets)
	printStatusMounts(s.Mounts)
	if !s.Mesh {
		fmt.Println("mesh: not joined — 'fabric join' puts this machine on a mesh")
		return nil
	}
	fmt.Printf("mesh: member %q, peer %s\n", s.MeshName, s.PeerID)
	if len(s.Peers) == 0 {
		fmt.Println("no members connected")
	}
	for _, p := range s.Peers {
		if p.Vault {
			fmt.Printf("  %-16s vault %s  circle %q %s\n", p.Name, p.Version, p.CircleName, p.Circle)
		} else {
			fmt.Printf("  %-16s (mesh member, no vault)\n", p.Name)
		}
	}
	return nil
}

func printStatusMounts(mounts []daemon.MountInfo) {
	if len(mounts) == 0 {
		return
	}
	fmt.Printf("mounts:\n")
	printMounts(mounts)
}

func cmdBucket(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric vault bucket create <name>")
	}
	if args[0] != "create" {
		return fmt.Errorf("unknown bucket subcommand %q (usage: fabric vault bucket create <name>)", args[0])
	}
	fs := flag.NewFlagSet("bucket create", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args[1:], -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric vault bucket create <name>")
	}
	// Signing happens here, where the passphrase prompt is — the daemon
	// only ever receives the signed genesis + policy.
	c, err := circle.Open(*statePath)
	if err != nil {
		return err
	}
	pass, err := passphrase()
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	genesis, policy, err := circle.SignBucket(priv, pos[0])
	if err != nil {
		return err
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	b, err := st.CreateBucket(genesis, policy)
	if err != nil {
		return err
	}
	fmt.Printf("bucket created: %q  %s\n", b.Name, b.ID)
	return nil
}

func cmdBuckets(args []string) error {
	fs := flag.NewFlagSet("buckets", flag.ExitOnError)
	statePath := stateFlag(fs)
	parse(fs, args, -1)
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	buckets, err := st.Buckets()
	if err != nil {
		return err
	}
	if len(buckets) == 0 {
		fmt.Println("no buckets — create one with: vault bucket create <name>")
		return nil
	}
	for _, b := range buckets {
		sub := b.Sub
		if sub == "" {
			sub = "-"
		}
		fmt.Printf("%s  %-6s %3d/%-3d  %s\n", b.ID[:16], sub, b.Held, b.Objects, b.Name)
	}
	return nil
}

func cmdSub(args []string) error {
	fs := flag.NewFlagSet("sub", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) < 1 || len(pos) > 2 {
		return fmt.Errorf("usage: fabric vault sub <bucket> [full|cache|none]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(pos) == 1 {
		buckets, err := st.Buckets()
		if err != nil {
			return err
		}
		for _, b := range buckets {
			if b.Name == pos[0] || strings.HasPrefix(b.ID, pos[0]) {
				mode := b.Sub
				if mode == "" {
					mode = "none (catalog + index only)"
				}
				fmt.Printf("%s  %s: %s — holding %d/%d blobs\n", b.ID[:16], b.Name, mode, b.Held, b.Objects)
				return nil
			}
		}
		return fmt.Errorf("no bucket matches %q", pos[0])
	}
	if err := st.Sub(pos[0], pos[1]); err != nil {
		return err
	}
	fmt.Printf("subscription set: %s -> %s\n", pos[0], pos[1])
	if pos[1] == "full" {
		fmt.Println("missing blobs will be fetched as peers are reachable")
	}
	return nil
}

func printObject(o daemon.ObjectInfo) {
	tagCol := ""
	if len(o.Tags) > 0 {
		tagCol = "  [" + strings.Join(o.Tags, " ") + "]"
	}
	fmt.Printf("%s  %s%s\n", o.ID[:12], o.Name, tagCol)
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	statePath := stateFlag(fs)
	tags := fs.String("tag", "", "comma-separated tags for the new objects")
	pos := parse(fs, args, -1)
	if len(pos) < 2 {
		return fmt.Errorf("usage: fabric vault put <bucket> <file...> [-tag t1,t2]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, path := range pos[1:] {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		name := strings.TrimLeft(path, "./")
		o, err := st.Put(pos[0], name, f, splitTags(*tags))
		f.Close()
		if err != nil {
			return err
		}
		fmt.Printf("put %s  %s  blob %s\n", o.ID[:12], o.Name, o.Blob[:12])
	}
	return nil
}

func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	statePath := stateFlag(fs)
	tags := fs.String("tag", "", "comma-separated tags; objects must carry all (facet intersection)")
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric vault ls <bucket> [-tag t1,t2]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	objs, err := st.List(pos[0], splitTags(*tags))
	if err != nil {
		return err
	}
	for _, o := range objs {
		printObject(o)
	}
	return nil
}

func cmdTag(args []string) error {
	fs := flag.NewFlagSet("tag", flag.ExitOnError)
	statePath := stateFlag(fs)
	// Flags stop being recognized after <bucket> <object-ref> — from there
	// on "-x" means "remove tag x", not a flag.
	pos := parse(fs, args, 2)
	if len(pos) < 3 {
		return fmt.Errorf("usage: fabric vault tag <bucket> <object-ref> [+tag ...] [-tag ...]")
	}
	var add, remove []string
	for _, m := range pos[2:] {
		switch {
		case strings.HasPrefix(m, "+"):
			add = append(add, m[1:])
		case strings.HasPrefix(m, "-"):
			remove = append(remove, m[1:])
		default:
			add = append(add, m)
		}
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := st.Tag(pos[0], pos[1], add, remove)
	if err != nil {
		return err
	}
	printObject(o)
	return nil
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	statePath := stateFlag(fs)
	out := fs.String("o", "", "output file (default: stdout)")
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric vault get <bucket> <object-ref> [-o file]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	r, err := st.Get(pos[0], pos[1])
	if err != nil {
		return err
	}
	defer r.Close()
	dst := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		dst = f
	}
	_, err = io.Copy(dst, r)
	return err
}

func cmdRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric vault rm <bucket> <object-ref>")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := st.Rm(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("tombstoned %s (%s) — blob retained per trash policy\n", o.ID[:12], o.Name)
	return nil
}

func cmdProject(args []string) error {
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric vault project <bucket> <dir>")
	}
	dir, err := filepath.Abs(pos[1])
	if err != nil {
		return err
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := st.Project(pos[0], dir)
	if err != nil {
		return err
	}
	fmt.Printf("projected %d objects into %s (read-only view — edits there are not writes)\n", n, dir)
	return nil
}

func cmdMount(args []string) error {
	fs := flag.NewFlagSet("mount", flag.ExitOnError)
	statePath := stateFlag(fs)
	debug := fs.Bool("debug", false, "show FUSE protocol logging (foreground only)")
	write := fs.Bool("write", false, "enable staged filesystem writes")
	foreground := fs.Bool("foreground", false, "serve the mount from this process instead of declaring it (debugging; dies with the terminal)")
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric vault mount <bucket> <dir> [-write] [-foreground [-debug]]")
	}
	mountpoint, err := filepath.Abs(pos[1])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("mount requires the running node daemon on %s", daemon.SocketPath(*statePath))
	}
	if *foreground {
		return foregroundMount(cl, *statePath, pos[0], mountpoint, *write, *debug)
	}
	m, err := cl.AddMount(mountpoint, pos[0], *write)
	if err != nil {
		return err
	}
	mode := "read-only"
	if m.Write {
		mode = "writable"
	}
	fmt.Printf("mount declared: the daemon serves bucket %.16s %s at %s\n", m.Bucket, mode, m.Dir)
	fmt.Printf("it persists across daemon restarts; remove with: fabric vault unmount %s\n", m.Dir)
	return nil
}

func cmdUnmount(args []string) error {
	fs := flag.NewFlagSet("unmount", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric vault unmount <dir>")
	}
	dir, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("unmount requires the running node daemon on %s", daemon.SocketPath(*statePath))
	}
	if err := cl.RemoveMount(dir); err != nil {
		return err
	}
	fmt.Printf("mount removed: %s\n", dir)
	return nil
}

func cmdMounts(args []string) error {
	fs := flag.NewFlagSet("mounts", flag.ExitOnError)
	statePath := stateFlag(fs)
	parse(fs, args, -1)
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("mounts requires the running node daemon on %s", daemon.SocketPath(*statePath))
	}
	mounts, err := cl.Mounts()
	if err != nil {
		return err
	}
	if len(mounts) == 0 {
		fmt.Println("no mounts declared — declare one with: fabric vault mount <bucket> <dir>")
		return nil
	}
	printMounts(mounts)
	return nil
}

func printMounts(mounts []daemon.MountInfo) {
	for _, m := range mounts {
		mode := "ro"
		if m.Write {
			mode = "rw"
		}
		state := "mounted"
		switch {
		case m.Error != "":
			state = "error: " + m.Error
		case !m.Mounted:
			state = "not mounted (daemon will retry)"
		}
		name := m.Name
		if name == "" {
			name = m.Bucket[:min(16, len(m.Bucket))]
		}
		fmt.Printf("  %s  %s  %s  %s\n", m.Dir, mode, name, state)
	}
}

// foregroundMount is the pre-ADR-0016 behavior, kept as a debugging escape
// hatch: the mount is served by this process and dies with it, and is not
// recorded in the daemon's mount table.
func foregroundMount(cl *daemon.Client, statePath, bucket, mountpoint string, write, debug bool) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	state, err := filepath.Abs(statePath)
	if err != nil {
		return err
	}
	// Stage beside the blob store rather than in the system temp dir: reads
	// and writes buffer whole objects, and /tmp is commonly a RAM-backed
	// tmpfs that one phone video can exhaust.
	server, err := fusefs.Mount(mountpoint, bucket, cl, fusefs.Options{
		Debug:    debug,
		Writable: write,
		StageDir: filepath.Join(state, "mount"),
	})
	if err != nil {
		return err
	}
	mode := "read-only"
	if write {
		mode = "writable"
	}
	fmt.Printf("mounted bucket %q %s at %s (foreground); unmount with Ctrl-C or fusermount3 -u %s\n", bucket, mode, mountpoint, mountpoint)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		server.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-sig:
		if err := server.Unmount(); err != nil {
			if lazyErr := daemon.LazyUnmount(mountpoint); lazyErr != nil {
				signal.Stop(sig)
				return fmt.Errorf("unmount: %w; lazy detach: %v (leave the mount directory and run fusermount3 -u %s)", err, lazyErr, mountpoint)
			}
		}
	}
	signal.Stop(sig)
	return nil
}
