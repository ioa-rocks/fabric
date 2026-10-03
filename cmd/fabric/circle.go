package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/state"
	vaultcli "ioa.rocks/fabric/vault/cli"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
	vaultstore "ioa.rocks/fabric/vault/store"
)

// The circle is the node's ownership layer (ADR 0017): a user key that
// buckets — and, next, astral subjects and grants — belong to. A node holds
// any number of circles under <state>/circles/<name> (ADR 0011: a device
// participates in several namespaces): its owner's personal circle, a
// shared "family" circle, … Each is managed here, not by any one data
// plane. Vault serves a bucket only to verified devices of the circle that
// owns it — mesh membership alone grants nothing.
func cmdCircle(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fabric circle init|join|export|attest|status")
	}
	rest := args[1:]
	switch args[0] {
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
	default:
		return fmt.Errorf("usage: fabric circle init|join|export|attest|status")
	}
}

func circleFlags(fs *flag.FlagSet) (statePath, vaultState *string) {
	statePath = stateFlag(fs)
	vaultState = fs.String("vault-state", vaultstore.DefaultPath(), "vault store directory")
	return
}

// circleRoot adopts older single-circle layouts into the node's circle
// root, then returns the root.
func circleRoot(statePath, vaultState string) (string, error) {
	root := circle.Root(statePath)
	for _, legacy := range []string{circle.LegacyDir(statePath), vaultState} {
		if did, err := circle.Migrate(root, legacy); err != nil {
			return "", fmt.Errorf("adopting the circle from %s: %w", legacy, err)
		} else if did {
			fmt.Fprintf(os.Stderr, "circle adopted from %s into %s (the old copy is left in place, unused)\n", legacy, root)
		}
	}
	return root, nil
}

// pickCircle resolves -circle: the named circle, or the only one.
func pickCircle(root, name string) (*circle.Circle, error) {
	if name == "" {
		return circle.Only(root)
	}
	return circle.ByName(root, name)
}

// passFor reads the passphrase for one circle — $CIRCLE_PASSPHRASE when
// set (one passphrase for every circle), else a prompt naming the circle.
func passFor(c *circle.Circle) (string, error) {
	if os.Getenv("CIRCLE_PASSPHRASE") != "" || os.Getenv("VAULT_PASSPHRASE") != "" {
		return vaultcli.Passphrase()
	}
	fmt.Fprintf(os.Stderr, "circle %q: ", c.Config.Name)
	return vaultcli.Passphrase()
}

func cmdCircleInit(args []string) error {
	fs := flag.NewFlagSet("circle init", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("name", "", "circle name (required; a single word — it names the directory and the -circle flag)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("circle init: -name is required")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	pass, err := vaultcli.NewPassphrase()
	if err != nil {
		return err
	}
	c, err := circle.Init(root, *name, pass)
	if err != nil {
		return err
	}
	fmt.Printf("circle created: %q  %s\n", c.Config.Name, c.Config.DID)
	fmt.Printf("user-key container: %s — back it up\n", c.KeyPath())
	if err := attestDevice(*statePath, c, pass); err != nil {
		return err
	}
	fmt.Println("another device joins with: fabric circle export -circle " + c.Config.Name + " <file>, then fabric circle join <file> there")
	if cl := vaultdaemon.TryClient(*vaultState); cl == nil {
		fmt.Println("restart the node daemon ('fabric up') if it was running without any circle, so it starts serving buckets")
	}
	return nil
}

func cmdCircleJoin(args []string) error {
	fs := flag.NewFlagSet("circle join", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle join <bundle-file | circle-dir>")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	b, err := circle.ReadBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "joining circle %q — its passphrase is needed to attest this device: ", b.Config.Name)
	pass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	c, err := circle.Join(root, b)
	if err != nil {
		return err
	}
	fmt.Printf("joined circle %q  %s\n", c.Config.Name, c.Config.DID)
	if err := attestDevice(*statePath, c, pass); err != nil {
		return err
	}
	if cl := vaultdaemon.TryClient(*vaultState); cl == nil {
		fmt.Println("restart the node daemon ('fabric up') if it was running without any circle; the catalog arrives via sync")
	} else {
		fmt.Println("the running daemon picks the circle up; its buckets arrive via sync")
	}
	return nil
}

func cmdCircleExport(args []string) error {
	fs := flag.NewFlagSet("circle export", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle to export (required when the node holds several)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle export [-circle <name>] <file>")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
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

// cmdCircleAttest (re)signs this device into its circles: for nodes that
// joined a circle before attestations existed, or that joined the mesh
// after the circle. Without -circle, every circle lacking an attestation.
func cmdCircleAttest(args []string) error {
	fs := flag.NewFlagSet("circle attest", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "attest into this circle only (default: every circle not yet attested)")
	fs.Parse(args)
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	var targets []*circle.Circle
	if *name != "" {
		c, err := circle.ByName(root, *name)
		if err != nil {
			return err
		}
		targets = []*circle.Circle{c}
	} else {
		all, err := circle.List(root)
		if err != nil {
			return err
		}
		for _, c := range all {
			if _, err := c.LoadAttestation(); err != nil {
				targets = append(targets, c)
			}
		}
		if len(targets) == 0 {
			fmt.Println("this device is attested into every circle it holds")
			return nil
		}
	}
	for _, c := range targets {
		pass, err := passFor(c)
		if err != nil {
			return err
		}
		if err := attestDevice(*statePath, c, pass); err != nil {
			return fmt.Errorf("circle %q: %w", c.Config.Name, err)
		}
	}
	return nil
}

func cmdCircleStatus(args []string) error {
	fs := flag.NewFlagSet("circle status", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	fs.Parse(args)
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	circles, err := circle.List(root)
	if err != nil {
		return err
	}
	if len(circles) == 0 {
		fmt.Printf("no circle on this node (%s) — 'fabric circle init -name <name>' mints one, 'fabric circle join <file>' joins an existing one\n", root)
		return nil
	}
	for _, c := range circles {
		fmt.Printf("circle %q  %s\n", c.Config.Name, c.Config.DID)
		fmt.Printf("  %s\n", c.Path)
		if _, err := c.LoadAttestation(); err == nil {
			fmt.Println("  device: attested (peers of the circle serve this device)")
		} else {
			fmt.Printf("  device: NOT attested — run 'fabric circle attest -circle %s'; until then no peer syncs this circle with this device\n", c.Config.Name)
		}
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
	for _, ci := range s.Circles {
		fmt.Printf("  %-16s %d bucket(s)\n", ci.Name, ci.Buckets)
	}
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
		case len(p.Shared) > 0:
			fmt.Printf("  %-16s vault %s  shares: %s (verified device)\n", p.Name, p.Version, strings.Join(p.Shared, ", "))
		case p.Vault && len(p.Circles) > 0:
			var claims []string
			for _, hc := range p.Circles {
				claims = append(claims, hc.Name)
			}
			fmt.Printf("  %-16s vault %s  claims %s — shares nothing verified with this device (attest, or no circle in common)\n", p.Name, p.Version, strings.Join(claims, ", "))
		case p.Vault:
			fmt.Printf("  %-16s vault %s  no circle\n", p.Name, p.Version)
		default:
			fmt.Printf("  %-16s (mesh member, no vault)\n", p.Name)
		}
	}
	return nil
}
