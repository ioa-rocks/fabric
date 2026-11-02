package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/keystore"
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
		return fmt.Errorf("usage: fabric circle init|join|export|attest|revoke|passphrase|status")
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
	case "revoke":
		return cmdCircleRevoke(rest)
	case "passphrase":
		return cmdCirclePassphrase(rest)
	case "status":
		return cmdCircleStatus(rest)
	default:
		return fmt.Errorf("usage: fabric circle init|join|export|attest|revoke|passphrase|status")
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
	fmt.Printf("device attested into circle %q until %s (%s) — a running daemon picks it up without restart\n", c.Config.Name, a.Expiry().Format("2006-01-02"), c.AttestationPath())
	return nil
}

// cmdCircleAttest (re)signs this device into its circles: for nodes that
// joined a circle before attestations existed, or that joined the mesh
// after the circle, and for renewal. Without -circle, every circle lacking
// a live attestation; with -expiring, also every one past half-life (the
// mesh's `renew -expiring` rule). Needs the circle key on this device.
func cmdCircleAttest(args []string) error {
	fs := flag.NewFlagSet("circle attest", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "attest into this circle only (default: every circle without a live attestation)")
	expiring := fs.Bool("expiring", false, "also renew every attestation past half-life")
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
		now := time.Now()
		for _, c := range all {
			a, err := c.LoadAttestation()
			switch {
			case err != nil, a.Valid(now) != nil, c.Revoked(a, now):
				targets = append(targets, c)
			case *expiring && a.PastHalfLife(now):
				targets = append(targets, c)
			}
		}
		if len(targets) == 0 {
			if *expiring {
				fmt.Println("this device holds a live attestation in every circle it holds, none past half-life")
			} else {
				fmt.Println("this device holds a live attestation in every circle it holds ('-expiring' renews those past half-life)")
			}
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

// cmdCirclePassphrase re-encrypts a circle's key container under a new
// passphrase on this device. The key is unchanged, so nothing is re-signed;
// when the circle is the mesh root (root merge), the root key container is
// the same key and is rewritten too. Other devices holding the circle are
// not reached: run it there as well, or re-export.
func cmdCirclePassphrase(args []string) error {
	fs := flag.NewFlagSet("circle passphrase", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle (required when the node holds several)")
	fs.Parse(args)
	if os.Getenv("CIRCLE_PASSPHRASE") != "" || os.Getenv("VAULT_PASSPHRASE") != "" {
		return fmt.Errorf("circle passphrase: unset CIRCLE_PASSPHRASE / VAULT_PASSPHRASE — the current and the new passphrase are both prompted")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "circle %q — current ", c.Config.Name)
	oldPass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	priv, err := c.Unlock(oldPass)
	if err != nil {
		return err
	}
	newPass, err := vaultcli.NewPassphrase()
	if err != nil {
		return err
	}
	if newPass == oldPass {
		return fmt.Errorf("circle passphrase: the new passphrase equals the current one")
	}
	if err := c.Rekey(oldPass, newPass); err != nil {
		return err
	}
	fmt.Printf("circle %q: key container re-encrypted (%s) — the key is unchanged, nothing to re-sign\n", c.Config.Name, c.KeyPath())
	// The root key container is this circle's key after the mesh-root merge:
	// keep both openable with one passphrase.
	if dir, err := state.Open(*statePath); err == nil {
		if rootSeed, err := keystore.LoadSeed(dir.KeystorePath(), oldPass); err == nil && bytes.Equal(rootSeed, priv.Seed()) {
			tmp := dir.KeystorePath() + ".tmp"
			if err := keystore.SaveSeed(tmp, rootSeed, newPass); err != nil {
				return fmt.Errorf("re-encrypting the root key container: %w", err)
			}
			if err := os.Rename(tmp, dir.KeystorePath()); err != nil {
				return fmt.Errorf("re-encrypting the root key container: %w", err)
			}
			fmt.Printf("root key container re-encrypted too (%s): it holds this circle's key since the mesh-root merge\n", dir.KeystorePath())
		}
	}
	fmt.Println("other devices holding this circle (circle export/join) still open it with the old passphrase — run 'fabric circle passphrase' there too, or re-export")
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
	now := time.Now()
	for _, c := range circles {
		fmt.Printf("circle %q  %s\n", c.Config.Name, c.Config.DID)
		fmt.Printf("  %s\n", c.Path)
		if _, err := os.Stat(c.KeyPath()); err == nil {
			fmt.Println("  role: owner device (holds the circle key)")
		} else {
			fmt.Println("  role: member device (no circle key)")
		}
		a, err := c.LoadAttestation()
		switch {
		case err != nil:
			fmt.Printf("  device: NOT attested — run 'fabric circle attest -circle %s'; until then no peer syncs this circle with this device\n", c.Config.Name)
		case c.Revoked(a, now):
			fmt.Printf("  device: REVOKED by the circle (as of its revocation list) — peers refuse this device; an owner device re-attests it to re-admit\n")
		case a.Valid(now) != nil:
			fmt.Printf("  device: attestation EXPIRED %s — run 'fabric circle attest -circle %s' (needs the circle key)\n", a.Expiry().Format("2006-01-02"), c.Config.Name)
		default:
			left := int(a.Expiry().Sub(now).Hours() / 24)
			note := ""
			if a.Legacy() {
				note = "; legacy attestation, window implied from issue date"
			}
			if a.PastHalfLife(now) {
				note += "; past half-life — renew with 'fabric circle attest -expiring'"
			}
			fmt.Printf("  device: attested until %s (%dd left%s)\n", a.Expiry().Format("2006-01-02"), left, note)
		}
		if rs, err := c.Revocations(now); err == nil && len(rs) > 0 {
			fmt.Printf("  revocations: %d held (latest %s)\n", len(rs), rs[len(rs)-1].Time().Format("2006-01-02"))
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

// cmdCircleRevoke signs a device out of a circle: every attestation it holds
// for the circle, issued up to now, is dead; devices of the circle learn it
// on their next circle exchange, and the running daemon here pushes it to
// the ones connected now. Needs the circle key — an owner device. A later
// attestation (an owner re-attesting the device) is a re-admission and
// stands.
func cmdCircleRevoke(args []string) error {
	fs := flag.NewFlagSet("circle revoke", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle (required when the node holds several)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle revoke [-circle <name>] <member-name | peer-id | fingerprint | did:key:…>")
	}
	target := fs.Arg(0)
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(c.KeyPath()); err != nil {
		return fmt.Errorf("this device holds no key for circle %q — revoke from an owner device", c.Config.Name)
	}
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	var client *daemon.Client
	if _, err := dir.LoadDeviceKey(); err == nil {
		client = daemon.NewClient(dir)
	}

	deviceDID, label := target, target
	if !strings.HasPrefix(target, "did:key:") {
		if client == nil {
			return fmt.Errorf("resolving %q needs this node's fabric identity and running daemon; give the device's did:key instead", target)
		}
		members, err := client.Members()
		if err != nil {
			return fmt.Errorf("resolving %q needs the running node daemon ('fabric up'), or give the device's did:key: %w", target, err)
		}
		var matches []daemon.MemberInfo
		for _, m := range members {
			if memberMatches(m, target) {
				matches = append(matches, m)
			}
		}
		switch len(matches) {
		case 0:
			return fmt.Errorf("no mesh member matches %q (see 'fabric status'); a device outside the mesh is revoked by its did:key", target)
		case 1:
		default:
			for _, m := range matches {
				fmt.Fprintf(os.Stderr, "  %s  %-16s %s\n", m.Fingerprint, m.Name, m.ID)
			}
			return fmt.Errorf("%q is ambiguous — %d members match", target, len(matches))
		}
		m := matches[0]
		if m.Self {
			return fmt.Errorf("%q is this device — revoke it from another owner device of the circle", m.Name)
		}
		deviceDID, label = cert.DIDForKey(ed25519.PublicKey(m.DevicePub)), m.Name
	}

	pass, err := passFor(c)
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	now := time.Now()
	r, err := circle.Revoke(priv, deviceDID, now)
	if err != nil {
		return err
	}
	if _, err := c.AddRevocations(now, r); err != nil {
		return err
	}
	fmt.Printf("revoked %s from circle %q as of %s\n", label, c.Config.Name, now.Format(time.RFC3339))
	fmt.Println("the device keeps whatever it already synced; devices of the circle stop serving it as they learn of this")
	if client != nil {
		if n, err := client.CircleRefresh(); err == nil {
			fmt.Printf("pushed to %d connected member(s); others learn it at their next circle exchange\n", n)
		} else {
			fmt.Println("no running node daemon here — connected devices learn it at their next circle exchange ('fabric up' pushes it)")
		}
	}
	fmt.Println("to re-admit the device later, attest it again on an owner device (an attestation issued after the revocation stands)")
	return nil
}
