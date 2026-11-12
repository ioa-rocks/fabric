// Package cli is the bucket command group ("fabric bucket <verb> …") — the
// CLI over the object-store API, one noun consumed once: every verb takes
// the bucket it acts on. Data commands work against a running daemon's
// control socket when there is one (the daemon owns the store while it
// runs) and fall back to opening the store directly — same operations
// either way (bucket-model memo §2: the API is the product; this is
// surface #1). Circle commands (init/join/status — the ownership layer)
// are fabric's own, not this package's: ADR 0017 hoists the circle out
// of vault.
//
// It is a package, not a main, so the one fabric binary can carry it
// (ADR 0013): cmd/fabric dispatches here on `fabric bucket …` and on a
// "vault" argv[0].
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

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/fusefs"
	"ioa.rocks/fabric/vault/store"

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
	case "create":
		err = cmdCreate(rest)
	case "list":
		err = cmdList(rest)
	case "place":
		err = cmdPlace(rest)
	case "mount":
		err = cmdMount(rest)
	case "unmount":
		err = cmdUnmount(rest)
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
	case "project":
		err = cmdProject(rest)
	case "policy":
		err = cmdPolicy(rest)
	case "trash":
		err = cmdTrash(rest)
	case "restore":
		err = cmdRestore(rest)
	case "versions":
		err = cmdVersions(rest)
	case "revert":
		err = cmdRevert(rest)
	case "conflicts":
		err = cmdConflicts(rest)
	case "resolve":
		err = cmdResolve(rest)
	case "held":
		err = cmdHeld(rest)
	case "reclaim":
		err = cmdReclaim(rest)
	case "scrub":
		err = cmdScrub(rest)
	case "-h", "-help", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "fabric bucket: unknown command %q\n\n", cmd)
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fabric bucket:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: fabric bucket <command> [flags]

Buckets are the data surface of the node; the circle that owns them is
'fabric circle'. The node daemon is 'fabric up' — it serves buckets when
a circle exists. Commands go through the running daemon's control socket,
or open the store directly when none runs.

  create   create <name> [-circle <name>] — mint a bucket (signs; needs the
           circle passphrase)
  list     list buckets and how this device holds each
  place    place <bucket> — show this device's placement, in detail
           place <bucket> full|cache|none — hold a complete copy / what
           gets accessed / read-only catalog and on-demand content
           place <bucket> folder <dir> — keep the bucket as a real
           directory the daemon syncs (a full placement); -rescan now
           place <bucket> full|cache -at <dir> — keep this bucket's blobs
           in a store rooted at <dir> (e.g. the NAS array); -at default
           returns to the device's own store
  mount    mount <bucket> <dir> [-write] — declare a FUSE mount the daemon
           serves from now on, across restarts, until 'unmount'
  unmount  unmount <dir> — remove a mount declaration and release the mount
  put      put <bucket> <file...> [-tag t1,t2] — add objects
  ls       ls <bucket> [-tag t1,t2] — list objects (tag intersection)
  tag      tag <bucket> <object-ref> [+tag ...] [-tag ...]
  get      get <bucket> <object-ref> [-o file] — read content
  rm       rm <bucket> <object-ref> — tombstone an object
  project  project <bucket> <dir> — materialize a read-only directory view
  policy   policy <bucket> [set key=value ...] — show or sign a policy revision
           (copies trash_days version_days ignore symlinks nested_repos
           hold_min_count hold_min_percent)
           trash_days: how long a deleted file stays restorable (0 reads
           as 30; negative keeps it for good)
           version_days: how long the content a file had before it was
           overwritten can be brought back (unset follows trash_days;
           off keeps none)
  trash    trash <bucket> — list tombstoned objects
  restore  restore <bucket> <object-ref> — revive a tombstoned object
           (refused once its content left the trash)
  versions versions <bucket> <object-ref> — earlier contents of a file
           this device saw replaced
  revert   revert <bucket> <object-ref> <version> — make an earlier
           content current again, on every device
  conflicts  conflicts <bucket> — list concurrent edits kept as conflict copies
  resolve  resolve <bucket> <object-ref> — settle a conflict for the kept version
  held     held <bucket> [accept|reject] — deletions parked for confirmation
  reclaim  reclaim [-dry-run] — remove content no bucket on this device
           retains: versions past version_days, deletions past trash_days. The
           daemon does this hourly; -dry-run only counts
  scrub    scrub [bucket] — read back held content and check it against
           its hash. Damaged content is set aside and fetched again from
           a peer; the daemon reads the whole device back every 30 days

Every command accepts -state <dir> (the store, default `+store.DefaultPath()+`)
and -circle-state <dir> (the circle, default `+circle.DefaultPath()+`),
before or after positional arguments. Signing commands read
$CIRCLE_PASSPHRASE or prompt.
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

// paths is the pair of directories every command may need: the store
// (per-device data) and the circle (ownership; only opened when a
// command signs or runs without a daemon).
type paths struct {
	store  *string
	circle *string
}

func pathFlags(fs *flag.FlagSet) paths {
	return paths{
		store:  fs.String("state", store.DefaultPath(), "store directory"),
		circle: fs.String("circle-state", circle.DefaultPath(), "circle root (the node's circles live under it)"),
	}
}

// openCircle opens one of the node's circles — the named one, or the only
// one when name is "".
func (p paths) openCircle(name string) (*circle.Circle, error) {
	if name == "" {
		return circle.Only(*p.circle)
	}
	return circle.ByName(*p.circle, name)
}

// openOwner opens the circle that owns a bucket, by the owner DID the
// store reports — the key that may sign that bucket's policy.
func (p paths) openOwner(ownerDID string) (*circle.Circle, error) {
	return circle.ByDID(*p.circle, ownerDID)
}

// Passphrase reads the circle passphrase from $CIRCLE_PASSPHRASE (or the
// pre-hoist $VAULT_PASSPHRASE) or an interactive no-echo prompt.
func Passphrase() (string, error) {
	if pass := os.Getenv("CIRCLE_PASSPHRASE"); pass != "" {
		return pass, nil
	}
	if pass := os.Getenv("VAULT_PASSPHRASE"); pass != "" {
		return pass, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no terminal for passphrase prompt; set CIRCLE_PASSPHRASE")
	}
	return prompt("circle user-key passphrase: ")
}

// NewPassphrase is Passphrase for a key that is being *created*: when it
// comes from a prompt it is asked twice, because a typo here locks the new
// key for good (there is no recovery for a circle key).
func NewPassphrase() (string, error) {
	if os.Getenv("CIRCLE_PASSPHRASE") != "" || os.Getenv("VAULT_PASSPHRASE") != "" || !term.IsTerminal(int(os.Stdin.Fd())) {
		return Passphrase()
	}
	for {
		first, err := prompt("new circle passphrase: ")
		if err != nil {
			return "", err
		}
		if first == "" {
			fmt.Fprintln(os.Stderr, "empty passphrase — try again")
			continue
		}
		again, err := prompt("repeat it: ")
		if err != nil {
			return "", err
		}
		if first == again {
			return first, nil
		}
		fmt.Fprintln(os.Stderr, "they differ — try again")
	}
}

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func splitTags(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	pth := pathFlags(fs)
	circleName := fs.String("circle", "", "owning circle (required when this device holds several)")
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric bucket create <name> [-circle <name>]")
	}
	// Signing happens here, where the passphrase prompt is — the daemon
	// only ever receives the signed genesis + policy.
	heldCircle, err := pth.openCircle(*circleName)
	if err != nil {
		return err
	}
	pass, err := Passphrase()
	if err != nil {
		return err
	}
	priv, err := heldCircle.Unlock(pass)
	if err != nil {
		return err
	}
	genesis, policy, err := store.SignBucket(priv, pos[0])
	if err != nil {
		return err
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	bkt, err := st.CreateBucket(genesis, policy)
	if err != nil {
		return err
	}
	fmt.Printf("bucket created: %q  %s  in circle %q\n", bkt.Name, bkt.ID, heldCircle.Config.Name)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	pth := pathFlags(fs)
	parse(fs, args, -1)
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	buckets, err := st.Buckets()
	if err != nil {
		return err
	}
	if len(buckets) == 0 {
		fmt.Println("no buckets — create one with: fabric bucket create <name>")
		return nil
	}
	for _, bkt := range buckets {
		fmt.Printf("%s  %-6s %3d/%-3d  %s%s\n", bkt.ID[:16], placementWord(bkt), bkt.Held, bkt.Files, bkt.Name, placementWhere(bkt))
	}
	return nil
}

// placementWord is the one-word placement column: none, cache, full, or
// folder (a folder replica is a full placement with a directory).
func placementWord(bkt daemon.BucketInfo) string {
	switch {
	case bkt.Folder != "":
		return "folder"
	case bkt.Sub == "":
		return "none"
	}
	return bkt.Sub
}

func placementWhere(bkt daemon.BucketInfo) string {
	where := ""
	if bkt.Folder != "" {
		where = "  " + bkt.Folder
	} else if bkt.Root != "" {
		where = "  at " + bkt.Root
	}
	for _, mountDir := range bkt.Mounts {
		where += "  mount " + mountDir
	}
	return where
}

func printObject(obj daemon.ObjectInfo) {
	tagCol := ""
	if len(obj.Tags) > 0 {
		tagCol = "  [" + strings.Join(obj.Tags, " ") + "]"
	}
	fmt.Printf("%s  %s%s\n", obj.ID[:12], obj.Name, tagCol)
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	pth := pathFlags(fs)
	tags := fs.String("tag", "", "comma-separated tags for the new objects")
	pos := parse(fs, args, -1)
	if len(pos) < 2 {
		return fmt.Errorf("usage: fabric bucket put <bucket> <file...> [-tag t1,t2]")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, path := range pos[1:] {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		name := strings.TrimLeft(path, "./")
		obj, err := st.Put(pos[0], name, file, splitTags(*tags))
		file.Close()
		if err != nil {
			return err
		}
		fmt.Printf("put %s  %s  blob %s\n", obj.ID[:12], obj.Name, obj.Blob[:12])
	}
	return nil
}

func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	pth := pathFlags(fs)
	tags := fs.String("tag", "", "comma-separated tags; objects must carry all (facet intersection)")
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric bucket ls <bucket> [-tag t1,t2]")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	objs, err := st.List(pos[0], splitTags(*tags))
	if err != nil {
		return err
	}
	for _, obj := range objs {
		printObject(obj)
	}
	return nil
}

func cmdTag(args []string) error {
	fs := flag.NewFlagSet("tag", flag.ExitOnError)
	pth := pathFlags(fs)
	// Flags stop being recognized after <bucket> <object-ref> — from there
	// on "-x" means "remove tag x", not a flag.
	pos := parse(fs, args, 2)
	if len(pos) < 3 {
		return fmt.Errorf("usage: fabric bucket tag <bucket> <object-ref> [+tag ...] [-tag ...]")
	}
	var add, remove []string
	for _, mod := range pos[2:] {
		switch {
		case strings.HasPrefix(mod, "+"):
			add = append(add, mod[1:])
		case strings.HasPrefix(mod, "-"):
			remove = append(remove, mod[1:])
		default:
			add = append(add, mod)
		}
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	obj, err := st.Tag(pos[0], pos[1], add, remove)
	if err != nil {
		return err
	}
	printObject(obj)
	return nil
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	pth := pathFlags(fs)
	out := fs.String("o", "", "output file (default: stdout)")
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket get <bucket> <object-ref> [-o file]")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	rc, err := st.Get(pos[0], pos[1])
	if err != nil {
		return err
	}
	defer rc.Close()
	dst := io.Writer(os.Stdout)
	if *out != "" {
		file, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer file.Close()
		dst = file
	}
	_, err = io.Copy(dst, rc)
	return err
}

func cmdRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket rm <bucket> <object-ref>")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	obj, err := st.Rm(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("tombstoned %s (%s) — blob retained per trash policy\n", obj.ID[:12], obj.Name)
	return nil
}

func cmdProject(args []string) error {
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket project <bucket> <dir>")
	}
	dir, err := filepath.Abs(pos[1])
	if err != nil {
		return err
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	count, err := st.Project(pos[0], dir)
	if err != nil {
		return err
	}
	fmt.Printf("projected %d objects into %s (read-only view — edits there are not writes)\n", count, dir)
	return nil
}

func cmdMount(args []string) error {
	fs := flag.NewFlagSet("mount", flag.ExitOnError)
	pth := pathFlags(fs)
	debug := fs.Bool("debug", false, "show FUSE protocol logging (foreground only)")
	write := fs.Bool("write", false, "enable staged filesystem writes")
	foreground := fs.Bool("foreground", false, "serve the mount from this process instead of declaring it (debugging; dies with the terminal)")
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket mount <bucket> <dir> [-write] [-foreground [-debug]]")
	}
	mountpoint, err := filepath.Abs(pos[1])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*pth.store)
	if cl == nil {
		return fmt.Errorf("mount requires the running node daemon on %s", daemon.SocketPath(*pth.store))
	}
	if *foreground {
		return foregroundMount(cl, *pth.store, pos[0], mountpoint, *write, *debug)
	}
	mount, err := cl.AddMount(mountpoint, pos[0], *write)
	if err != nil {
		return err
	}
	mode := "read-only"
	if mount.Write {
		mode = "writable"
	}
	fmt.Printf("mount declared: the daemon serves bucket %.16s %s at %s\n", mount.Bucket, mode, mount.Dir)
	fmt.Printf("it persists across daemon restarts; remove with: fabric bucket unmount %s\n", mount.Dir)
	return nil
}

func cmdUnmount(args []string) error {
	fs := flag.NewFlagSet("unmount", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric bucket unmount <dir>")
	}
	dir, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*pth.store)
	if cl == nil {
		return fmt.Errorf("unmount requires the running node daemon on %s", daemon.SocketPath(*pth.store))
	}
	if err := cl.RemoveMount(dir); err != nil {
		return err
	}
	fmt.Printf("mount removed: %s\n", dir)
	return nil
}

// PrintMounts renders mount lines (shared with 'fabric circle status').
func PrintMounts(mounts []daemon.MountInfo) {
	for _, mount := range mounts {
		mode := "ro"
		if mount.Write {
			mode = "rw"
		}
		state := "mounted"
		switch {
		case mount.Error != "":
			state = "error: " + mount.Error
		case !mount.Mounted:
			state = "not mounted (daemon will retry)"
		}
		name := mount.Name
		if name == "" {
			name = mount.Bucket[:min(16, len(mount.Bucket))]
		}
		fmt.Printf("  %s  %s  %s  %s\n", mount.Dir, mode, name, state)
	}
}

// foregroundMount is the pre-ADR-0016 behavior, kept as a debugging escape
// hatch: the mount is served by this process and dies with it, and is not
// recorded in the daemon's mount table.
func foregroundMount(cl *daemon.Client, statePath, bucket, mountpoint string, write, debug bool) error {
	statePath = store.ExistingPath(statePath)
	if write {
		info, err := findBucket(clientStore{cl}, bucket)
		if err != nil {
			return err
		}
		if info.Sub != store.SubCache && info.Sub != store.SubFull {
			return fmt.Errorf("%w: choose cache or full before mounting writable", store.ErrReadOnlyPlacement)
		}
	}
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
