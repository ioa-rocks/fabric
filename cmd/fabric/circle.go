package main

import (
	"flag"
	"fmt"
	"os"

	"crypto/ed25519"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/state"
	vaultcli "ioa.rocks/fabric/vault/cli"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
	vaultstore "ioa.rocks/fabric/vault/store"
	"time"
)

// The circle is the node's ownership layer (ADR 0017): a user key that
// buckets — and, next, astral subjects and grants — belong to. It lives
// under the fabric state directory, beside the device key, and is
// managed here rather than by any one data plane. One circle per node
// today.

func cmdCircle(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric circle init|join|export|attest|status")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return cmdCircleInit(rest)
	case "join":
		return cmdCircleJoin(rest)
	case "export":
		return cmdCircleExport(rest)
	case "attest":
		return cmdCircleAttest(rest)
	case "status":
		return cmdCircleStatus(rest)
	}
	return fmt.Errorf("unknown circle command %q (init|join|export|status)", sub)
}

// circleFlags: the circle lives in <state>/circle; -vault-state is where a
// pre-hoist circle would still be found (and where the store is).
func circleFlags(fs *flag.FlagSet) (statePath, vaultState *string) {
	statePath = stateFlag(fs)
	vaultState = fs.String("vault-state", vaultstore.DefaultPath(), "vault store directory")
	return
}

// openCircle adopts a pre-hoist circle from the vault store directory if
// that is where it still lives, then opens the node's circle.
func openCircle(statePath, vaultState string) (*circle.Circle, error) {
	dir := circle.Dir(statePath)
	if did, err := circle.Migrate(dir, vaultState); err != nil {
		return nil, fmt.Errorf("adopting the circle from %s: %w", vaultState, err)
	} else if did {
		fmt.Fprintf(os.Stderr, "circle adopted from %s into %s (the old copy is left in place, unused)\n", vaultState, dir)
	}
	return circle.Open(dir)
}

func cmdCircleInit(args []string) error {
	fs := flag.NewFlagSet("circle init", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("name", "", "circle owner label (required)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("circle init: -name is required")
	}
	if circle.Exists(*vaultState) {
		return fmt.Errorf("a circle already lives in %s — 'fabric circle status' adopts it", *vaultState)
	}
	pass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	c, err := circle.Init(circle.Dir(*statePath), *name, pass)
	if err != nil {
		return err
	}
	fmt.Printf("circle created: %q  %s\n", c.Config.Name, c.Config.DID)
	if err := attestDevice(*statePath, c, pass); err != nil {
		return err
	}
	fmt.Printf("user-key container: %s — back it up\n", c.KeyPath())
	fmt.Println("another device of yours joins with: fabric circle export <file>, then fabric circle join <file> there")
	return nil
}

func cmdCircleJoin(args []string) error {
	fs := flag.NewFlagSet("circle join", flag.ExitOnError)
	statePath, _ := circleFlags(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle join <bundle-file | circle-dir>")
	}
	b, err := circle.ReadBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	pass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	c, err := circle.Join(circle.Dir(*statePath), b)
	if err != nil {
		return err
	}
	fmt.Printf("joined circle %q  %s\n", c.Config.Name, c.Config.DID)
	if err := attestDevice(*statePath, c, pass); err != nil {
		return err
	}
	fmt.Println("restart the node daemon ('fabric up') so it serves buckets; the catalog arrives via sync")
	return nil
}

func cmdCircleExport(args []string) error {
	fs := flag.NewFlagSet("circle export", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle export <file>")
	}
	c, err := openCircle(*statePath, *vaultState)
	if err != nil {
		return err
	}
	b, err := c.Export()
	if err != nil {
		return err
	}
	if err := circle.WriteBundle(fs.Arg(0), b); err != nil {
		return err
	}
	fmt.Printf("circle %q exported to %s — it carries the key container (passphrase-protected); move it privately and delete it after joining\n", c.Config.Name, fs.Arg(0))
	return nil
}

// attestDevice signs this node's fabric device key into the circle
// (circle.Attest) — the statement peers verify before they sync with it.
// Needs the fabric identity; before 'fabric join' it only says what to run.
func attestDevice(statePath string, c *circle.Circle, pass string) error {
	dir, err := state.Open(statePath)
	if err != nil {
		return err
	}
	devPriv, err := dir.LoadDeviceKey()
	if err != nil {
		fmt.Println("no fabric identity on this node yet — after 'fabric join', run 'fabric circle attest' so the circle's other devices serve this one")
		return nil
	}
	raw, err := devPriv.GetPublic().Raw()
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	a, err := circle.Attest(priv, ed25519.PublicKey(raw), time.Now())
	if err != nil {
		return err
	}
	if err := c.SaveAttestation(a); err != nil {
		return err
	}
	fmt.Printf("device attested into circle %q (%s) — a running daemon picks it up without restart\n", c.Config.Name, c.AttestationPath())
	return nil
}

// cmdCircleAttest (re)signs this device into its circle: for nodes that
// joined the circle before attestations existed, or that joined the mesh
// after the circle.
func cmdCircleAttest(args []string) error {
	fs := flag.NewFlagSet("circle attest", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	fs.Parse(args)
	c, err := openCircle(*statePath, *vaultState)
	if err != nil {
		return err
	}
	pass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	return attestDevice(*statePath, c, pass)
}

func cmdCircleStatus(args []string) error {
	fs := flag.NewFlagSet("circle status", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	fs.Parse(args)
	c, err := openCircle(*statePath, *vaultState)
	if err != nil {
		return err
	}
	fmt.Printf("circle %q  %s\n", c.Config.Name, c.Config.DID)
	fmt.Printf("  %s\n", c.Path)
	if _, err := c.LoadAttestation(); err == nil {
		fmt.Println("  device: attested (peers of the circle serve this device)")
	} else {
		fmt.Println("  device: NOT attested — run 'fabric circle attest'; until then no peer syncs with this device")
	}
	cl := vaultdaemon.TryClient(*vaultState)
	if cl == nil {
		fmt.Printf("buckets: no daemon on %s (the node daemon is 'fabric up')\n", vaultdaemon.SocketPath(*vaultState))
		return nil
	}
	s, err := cl.Status()
	if err != nil {
		return err
	}
	fmt.Printf("buckets: daemon %s serves %d bucket(s) from %s ('fabric bucket list')\n", s.Version, s.Buckets, *vaultState)
	if len(s.Mounts) > 0 {
		fmt.Println("mounts:")
		vaultcli.PrintMounts(s.Mounts)
	}
	if len(s.Folders) > 0 {
		fmt.Println("folders:")
		vaultcli.PrintFolders(s.Folders)
	}
	if !s.Mesh {
		fmt.Println("mesh: not joined — 'fabric join' puts this machine on a mesh")
		return nil
	}
	fmt.Printf("mesh: member %q, peer %s\n", s.MeshName, s.PeerID)
	if len(s.Peers) == 0 {
		fmt.Println("no members connected")
	}
	for _, p := range s.Peers {
		switch {
		case p.Vault && p.Circle == c.Config.DID:
			fmt.Printf("  %-16s vault %s  same circle\n", p.Name, p.Version)
		case p.Vault:
			fmt.Printf("  %-16s vault %s  circle %q %s\n", p.Name, p.Version, p.CircleName, p.Circle)
		default:
			fmt.Printf("  %-16s (mesh member, no vault)\n", p.Name)
		}
	}
	return nil
}
