// Command vault is the CLI over the object-store API. Data commands work
// against a running daemon's control socket when there is one (the daemon
// owns the store while it runs) and fall back to opening the state
// directly — same operations either way (bucket-model memo §2: the API is
// the product; this is surface #1).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/daemon"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "status":
		err = cmdStatus(args)
	case "buckets":
		err = cmdBuckets(args)
	case "bucket":
		err = cmdBucket(args)
	case "put":
		err = cmdPut(args)
	case "ls":
		err = cmdLs(args)
	case "tag":
		err = cmdTag(args)
	case "get":
		err = cmdGet(args)
	case "rm":
		err = cmdRm(args)
	case "sub":
		err = cmdSub(args)
	case "project":
		err = cmdProject(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: vault <command> [flags]

The data surface of the node. The node daemon itself is 'fabric up' —
it activates the vault subsystem when circle state exists (ADR 0013);
mesh membership is 'fabric join'. Data commands go through the running
daemon's control socket, or open the state directly when none runs.

  init     create a circle on this device (-name required)
  status   show daemon state: circle, mesh, connected vault peers
  bucket   bucket create <name> — mint a bucket (signs; needs passphrase)
  buckets  list buckets
  put      put <bucket> <file...> [-tag t1,t2] — add objects
  ls       ls <bucket> [-tag t1,t2] — list objects (tag intersection)
  tag      tag <bucket> <object-ref> [+tag ...] [-tag ...]
  get      get <bucket> <object-ref> [-o file] — read content
  rm       rm <bucket> <object-ref> — tombstone an object
  sub      sub <bucket> [full|cache|none] — this device's placement commitment
  project  project <bucket> <dir> — materialize a read-only directory view

Every command accepts -state <dir> (default `+circle.DefaultPath()+`).
Signing commands read $VAULT_PASSPHRASE or prompt.
`)
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
	fs.Parse(args)
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
	fs.Parse(args)
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
	if !s.Mesh {
		fmt.Println("mesh: not joined — 'fabric join' puts this machine on a mesh")
		return nil
	}
	fmt.Printf("mesh: member %q, peer %s\n", s.MeshName, s.PeerID)
	if len(s.Peers) == 0 {
		fmt.Println("no members connected")
		return nil
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

func cmdBucket(args []string) error {
	if len(args) < 1 || args[0] != "create" {
		return fmt.Errorf("usage: vault bucket create <name>")
	}
	fs := flag.NewFlagSet("bucket create", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args[1:])
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: vault bucket create <name>")
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
	genesis, policy, err := circle.SignBucket(priv, fs.Arg(0))
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
	fs.Parse(args)
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
	fs.Parse(args)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("usage: vault sub <bucket> [full|cache|none]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	if fs.NArg() == 1 {
		buckets, err := st.Buckets()
		if err != nil {
			return err
		}
		for _, b := range buckets {
			if b.Name == fs.Arg(0) || strings.HasPrefix(b.ID, fs.Arg(0)) {
				mode := b.Sub
				if mode == "" {
					mode = "none (catalog + index only)"
				}
				fmt.Printf("%s  %s: %s — holding %d/%d blobs\n", b.ID[:16], b.Name, mode, b.Held, b.Objects)
				return nil
			}
		}
		return fmt.Errorf("no bucket matches %q", fs.Arg(0))
	}
	if err := st.Sub(fs.Arg(0), fs.Arg(1)); err != nil {
		return err
	}
	fmt.Printf("subscription set: %s -> %s\n", fs.Arg(0), fs.Arg(1))
	if fs.Arg(1) == "full" {
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
	fs.Parse(args)
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: vault put <bucket> <file...> [-tag t1,t2]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, path := range fs.Args()[1:] {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		name := strings.TrimLeft(path, "./")
		o, err := st.Put(fs.Arg(0), name, f, splitTags(*tags))
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
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: vault ls <bucket> [-tag t1,t2]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	objs, err := st.List(fs.Arg(0), splitTags(*tags))
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
	fs.Parse(args)
	if fs.NArg() < 3 {
		return fmt.Errorf("usage: vault tag <bucket> <object-ref> [+tag ...] [-tag ...]")
	}
	var add, remove []string
	for _, m := range fs.Args()[2:] {
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
	o, err := st.Tag(fs.Arg(0), fs.Arg(1), add, remove)
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
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: vault get <bucket> <object-ref> [-o file]")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	r, err := st.Get(fs.Arg(0), fs.Arg(1))
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
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: vault rm <bucket> <object-ref>")
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := st.Rm(fs.Arg(0), fs.Arg(1))
	if err != nil {
		return err
	}
	fmt.Printf("tombstoned %s (%s) — blob retained per trash policy\n", o.ID[:12], o.Name)
	return nil
}

func cmdProject(args []string) error {
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: vault project <bucket> <dir>")
	}
	dir, err := filepath.Abs(fs.Arg(1))
	if err != nil {
		return err
	}
	st, err := openStore(*statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := st.Project(fs.Arg(0), dir)
	if err != nil {
		return err
	}
	fmt.Printf("projected %d objects into %s (read-only view — edits there are not writes)\n", n, dir)
	return nil
}
