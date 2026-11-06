package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/libp2p/go-libp2p/core/peer"
	"ioa.rocks/fabric/astral"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/fabricnet"
	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/state"
	"ioa.rocks/fabric/statement"
	"ioa.rocks/fabric/tunbridge"
	vaultcli "ioa.rocks/fabric/vault/cli"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
	vaultstore "ioa.rocks/fabric/vault/store"
)

// The circle is the node's ownership layer (ADR 0017): a user key that
// buckets — and, next, astral subjects and grants — belong to. A node holds
// any number of circles under <state>/circles/<name> (ADR 0011: a device
// participates in several circles): its owner's personal circle, a
// shared "family" circle, … Each is managed here, not by any one data
// plane. Vault serves a bucket only to verified devices of the circle that
// owns it — mesh membership alone grants nothing.
func cmdCircle(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fabric circle init|admit|join|export|renew|revoke|passphrase|grant|status")
	}
	rest := args[1:]
	switch args[0] {
	case "init":
		return cmdCircleInit(rest)
	case "admit":
		return cmdCircleAdmit(rest)
	case "join":
		return cmdCircleJoin(rest)
	case "export":
		return cmdCircleExport(rest)
	case "renew", "attest": // "attest": the name before 2026-11-05
		return cmdCircleRenew(rest)
	case "revoke":
		return cmdCircleRevoke(rest)
	case "passphrase":
		return cmdCirclePassphrase(rest)
	case "grant":
		return cmdCircleGrant(rest)
	case "status":
		return cmdCircleStatus(rest)
	default:
		return fmt.Errorf("usage: fabric circle init|admit|join|export|renew|revoke|passphrase|grant|status")
	}
}

func circleFlags(fs *flag.FlagSet) (statePath, vaultState *string) {
	statePath = stateFlag(fs)
	vaultState = fs.String("vault-state", vaultstore.DefaultPath(), "vault store directory")
	return
}

// circleRoot is the node's circle root. (Until 2026-11-06 it also adopted
// the two pre-multi-circle layouts — <state>/circle and the circle files
// inside the vault store directory — into the root; every fleet node has
// been on circles/<name> since 2026-11-02, so the adoption is gone.)
func circleRoot(statePath, _ string) (string, error) {
	return circle.Root(statePath), nil
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
	subnet := fs.String("subnet", "auto", "the circle's overlay range (CIDR): devices admitted with -tun get an address in it; 'auto' derives a /24 in 100.64.0.0/10 from the circle DID, 'none' for no overlay")
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
	prefix, err := circlePrefix(root, c, *subnet)
	if err != nil {
		return err
	}
	if err := c.SetPrefix(prefix); err != nil {
		return err
	}
	fmt.Printf("circle created: %q  %s\n", c.Config.Name, c.Config.DID)
	if prefix != "" {
		fmt.Printf("overlay range %s (devices admitted with -tun get an address in it)\n", prefix)
	}
	fmt.Printf("user-key container: %s — back it up\n", c.KeyPath())
	if err := admitSelf(*statePath, c, pass); err != nil {
		return err
	}
	fmt.Println("admit a device with: fabric circle admit <member> -circle " + c.Config.Name + " -out <file>, then fabric circle join <file> there (no key copy)")
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
	if !b.HasKey() {
		// A device bundle: the admission must be for this very device.
		a, err := b.DeviceAdmission()
		if err != nil {
			return err
		}
		dir, err := state.Open(*statePath)
		if err != nil {
			return err
		}
		devPriv, err := dir.LoadDeviceKey()
		if err != nil {
			return fmt.Errorf("this node has no fabric identity yet (device.key): on a fresh machine run 'fabric join <bundle>' instead")
		}
		raw, err := devPriv.GetPublic().Raw()
		if err != nil {
			return err
		}
		if err := a.Verify(ed25519.PublicKey(raw), time.Now()); err != nil {
			return fmt.Errorf("the bundle's admission is not for this device: %w (the owner must admit this device's key: %s)", err, did.ForKey(ed25519.PublicKey(raw)))
		}
		c, err := circle.Join(root, b)
		if err != nil {
			return err
		}
		fmt.Printf("joined circle %q  %s as a %s (no key on this device)\n", c.Config.Name, c.Config.DID, a.Role())
		fmt.Printf("admitted until %s; gate hints: %s\n", a.Expiry().Format("2006-01-02"), strings.Join(c.Config.Gates, " "))
		if cl := vaultdaemon.TryClient(*vaultState); cl == nil {
			fmt.Println("start the node daemon ('fabric up') if it is not running; a running one picks the circle up")
		} else {
			fmt.Println("the running daemon picks the circle up; its buckets arrive via sync")
		}
		return nil
	}
	fmt.Fprintln(os.Stderr, "this bundle carries the circle KEY: joining makes this device a co-owner — it can mint buckets, admit and revoke devices, and revoking it later cannot take that back (a one-way door). For a device that should not own the circle, ask an owner for 'fabric circle admit' instead.")
	fmt.Fprintf(os.Stderr, "joining circle %q — its passphrase is needed to admit this device: ", b.Config.Name)
	pass, err := vaultcli.Passphrase()
	if err != nil {
		return err
	}
	c, err := circle.Join(root, b)
	if err != nil {
		return err
	}
	fmt.Printf("joined circle %q  %s as an owner (holds the key)\n", c.Config.Name, c.Config.DID)
	if err := admitSelf(*statePath, c, pass); err != nil {
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
	if !c.HasKey() {
		return fmt.Errorf("this device holds no key for circle %q — only an owner device can export it (a device bundle comes from 'fabric circle admit' on an owner)", c.Config.Name)
	}
	b, err := c.Export()
	if err != nil {
		return err
	}
	if err := circle.WriteBundle(fs.Arg(0), b); err != nil {
		return err
	}
	fmt.Printf("circle %q exported to %s — it carries the key container (passphrase-protected); move it privately and delete it after joining\n", c.Config.Name, fs.Arg(0))
	fmt.Println("note: whoever joins this bundle becomes a co-owner for good (a one-way door); for a device that should not own the circle use 'fabric circle admit' instead")
	return nil
}

// admitSelf signs this node's fabric device key into the circle
// (circle.Admit) — the statement peers verify before they sync with it.
// Needs the fabric identity; before 'fabric join' it only says what to run.
func admitSelf(statePath string, c *circle.Circle, pass string) error {
	dir, err := state.Open(statePath)
	if err != nil {
		return err
	}
	devPriv, err := dir.LoadDeviceKey()
	if err != nil {
		fmt.Println("no fabric identity on this node yet — after 'fabric join', run 'fabric circle renew' so the circle's other devices serve this one")
		return nil
	}
	raw, err := devPriv.GetPublic().Raw()
	if err != nil {
		return err
	}
	if !c.HasKey() {
		return fmt.Errorf("this device holds no key for circle %q — an owner device renews it with 'fabric circle admit %s -circle %s'", c.Config.Name, did.ForKey(ed25519.PublicKey(raw)), c.Config.Name)
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	// Carry the device's current admission in this circle forward: the
	// membership cert when the circle is the one it was joined in (name,
	// overlay address, owner verbs), else the admission on disk. A bare
	// re-admission would outrank the named one by expiry in every
	// roster and strip the device of its address.
	var prev *statement.Statement
	firstCircle := false
	if own, err := dir.LoadCert(); err == nil && own.Stmt != nil && own.Payload.Sub == c.Config.DID {
		prev, firstCircle = own.Stmt, true
	} else if cur, err := c.LoadAdmission(); err == nil && cur.Stmt != nil {
		prev = cur.Stmt
	}
	now := time.Now()
	a, err := circle.Renew(priv, prev, c.Config.DID, ed25519.PublicKey(raw), now, circle.DefaultValidity)
	if err != nil {
		return err
	}
	if err := c.SaveAdmission(a); err != nil {
		return err
	}
	kept := ""
	if a.Name != "" || a.IP != "" {
		kept = fmt.Sprintf(" as %s", strings.TrimSpace(a.Name+" "+a.IP))
	}
	fmt.Printf("device admitted into circle %q%s until %s (%s) — a running daemon picks it up without restart\n", c.Config.Name, kept, a.Expiry().Format("2006-01-02"), c.AdmissionPath())
	if firstCircle {
		// The circle is the one the device was joined in: the admission
		// *is* its membership cert there (same root, same statement
		// shape), so the transport cert follows — through the daemon when
		// it runs (spec §5 renewal: adopted and gossiped as a MemberAdded
		// event), else written to cert.cbor (Codex review, 2026-11-05:
		// the stored admission changed while the handshake kept
		// presenting the old cert).
		return renewOwnCertFrom(dir, priv, a, now)
	}
	return nil
}

// certDue reports whether the membership cert needs re-signing: expired,
// or past half-life when renewing the expiring.
func certDue(own *cert.Cert, now time.Time, expiring bool) bool {
	nbf, exp := time.Unix(own.Payload.Nbf, 0), own.Expiry()
	if !now.Before(exp) {
		return true
	}
	return expiring && now.After(nbf.Add(exp.Sub(nbf)/2))
}

// renewOwnCertFrom adopts a first-circle admission as this device's
// membership cert.
func renewOwnCertFrom(dir state.Dir, root ed25519.PrivateKey, a *circle.Admission, now time.Time) error {
	view, err := cert.FromStatement(a.Stmt)
	if err != nil {
		return fmt.Errorf("admission as membership cert: %w", err)
	}
	client := daemon.NewClient(dir)
	if _, err := client.Status(); err == nil {
		ev, err := event.NewAdded(root, view, now)
		if err != nil {
			return err
		}
		raw, err := ev.Marshal()
		if err != nil {
			return err
		}
		if err := client.Renew(raw); err != nil {
			return fmt.Errorf("renewing the membership cert through the daemon: %w", err)
		}
		fmt.Println("membership cert renewed with it (the daemon presents the new one and gossips it)")
		return nil
	}
	if err := dir.SaveCert(view); err != nil {
		return err
	}
	fmt.Println("membership cert renewed with it (cert.cbor; the daemon is not running)")
	return nil
}

// cmdCircleRenew (re)signs this device into its circles: for nodes that
// joined a circle before admissions existed, or that joined the mesh
// after the circle, and for renewal. Without -circle, every circle lacking
// a live admission; with -expiring, also every one past half-life (the
// mesh's `renew -expiring` rule). Needs the circle key on this device.
func cmdCircleRenew(args []string) error {
	fs := flag.NewFlagSet("circle renew", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "admit into this circle only (default: every circle without a live admission)")
	expiring := fs.Bool("expiring", false, "also renew every admission past half-life")
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
		// For the circle the device was joined in, the membership cert is
		// the transport admission: it is due when it is, whatever the
		// admission file says (Codex review, 2026-11-05).
		var own *cert.Cert
		if dir, err := state.Open(*statePath); err == nil {
			own, _ = dir.LoadCert()
		}
		for _, c := range all {
			a, err := c.LoadAdmission()
			switch {
			case err != nil, a.Valid(now) != nil, c.Revoked(a, now):
				targets = append(targets, c)
			case *expiring && a.PastHalfLife(now):
				targets = append(targets, c)
			case own != nil && own.Payload.Sub == c.Config.DID && certDue(own, now, *expiring):
				targets = append(targets, c)
			}
		}
		if len(targets) == 0 {
			if *expiring {
				fmt.Println("this device holds a live admission in every circle it holds, none past half-life")
			} else {
				fmt.Println("this device holds a live admission in every circle it holds ('-expiring' renews those past half-life)")
			}
			return nil
		}
	}
	for _, c := range targets {
		if !c.HasKey() {
			fmt.Fprintf(os.Stderr, "circle %q: this device holds no key — an owner device renews it with 'fabric circle admit'\n", c.Config.Name)
			continue
		}
		pass, err := passFor(c)
		if err != nil {
			return err
		}
		if err := admitSelf(*statePath, c, pass); err != nil {
			return fmt.Errorf("circle %q: %w", c.Config.Name, err)
		}
	}
	return nil
}

// cmdCirclePassphrase re-encrypts a circle's key container under a new
// passphrase on this device. The key is unchanged, so nothing is re-signed;
// when the circle's key is the root (circle `main` since the 2026-11-02
// migration), the root key container is the same key and is rewritten too. Other devices holding the circle are
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
	// The membership cert doubles as the admission into the circle that
	// issued it (one admission per device since the mesh-root merge).
	var ownCert *cert.Cert
	if dir, err := state.Open(*statePath); err == nil {
		ownCert, _ = dir.LoadCert()
	}
	for _, c := range circles {
		fmt.Printf("circle %q  %s\n", c.Config.Name, c.Config.DID)
		fmt.Printf("  %s\n", c.Path)
		if c.Config.Prefix != "" {
			fmt.Printf("  overlay: %s\n", c.Config.Prefix)
		}
		if len(c.Config.Gates) > 0 {
			fmt.Printf("  gates: %s\n", strings.Join(c.Config.Gates, " "))
		}
		a, err := c.LoadAdmission()
		if (err != nil || a.Valid(now) != nil) && ownCert != nil && ownCert.Stmt != nil && ownCert.Payload.Sub == c.Config.DID {
			if raw, merr := ownCert.Marshal(); merr == nil {
				if fromCert, uerr := circle.UnmarshalAdmission(raw); uerr == nil {
					a, err = fromCert, nil
				}
			}
		}
		switch {
		case c.HasKey():
			fmt.Println("  role: owner (holds the circle key: mints buckets, admits and revokes devices)")
		case err == nil:
			fmt.Printf("  role: %s (no key on this device)\n", a.Role())
		default:
			fmt.Println("  role: device (no key on this device)")
		}
		renew := fmt.Sprintf("run 'fabric circle renew -circle %s'", c.Config.Name)
		if !c.HasKey() {
			renew = "an owner device re-admits it with 'fabric circle admit'"
		}
		switch {
		case err != nil:
			fmt.Printf("  device: NOT admitted — %s; until then no peer serves this circle to this device\n", renew)
		case c.Revoked(a, now):
			fmt.Printf("  device: REVOKED by the circle (as of its revocation list) — peers refuse this device; an owner device re-admits it\n")
		case a.Valid(now) != nil:
			fmt.Printf("  device: admission EXPIRED %s — %s\n", a.Expiry().Format("2006-01-02"), renew)
		default:
			left := int(a.Expiry().Sub(now).Hours() / 24)
			note := ""
			if a.Legacy() {
				note = "; legacy admission, window implied from issue date"
			}
			if a.PastHalfLife(now) {
				if c.HasKey() {
					note += "; past half-life — renew with 'fabric circle renew -expiring'"
				} else {
					note += "; past half-life — an owner device re-admits it"
				}
			}
			fmt.Printf("  device: admitted until %s (%dd left%s)\n", a.Expiry().Format("2006-01-02"), left, note)
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
			fmt.Printf("  %-16s vault %s  claims %s — shares nothing verified with this device (admit, or no circle in common)\n", p.Name, p.Version, strings.Join(claims, ", "))
		case p.Vault:
			fmt.Printf("  %-16s vault %s  no circle\n", p.Name, p.Version)
		default:
			fmt.Printf("  %-16s (mesh member, no vault)\n", p.Name)
		}
	}
	return nil
}

// cmdCircleRevoke signs a device out of a circle: every admission it holds
// for the circle, issued up to now, is dead; devices of the circle learn it
// on their next circle exchange, and the running daemon here pushes it to
// the ones connected now. Needs the circle key — an owner device. A later
// admission (an owner re-admitting the device) is a re-admission and
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
	if !c.HasKey() {
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
	deviceDID, label, err := resolveDevice(client, target)
	if err != nil {
		return err
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
	fmt.Println("to re-admit the device later, admit it again on an owner device (an admission issued after the revocation stands)")
	return nil
}

// resolveDevice turns a device reference — did:key, or a member's name,
// peer ID or fingerprint known to the running daemon — into its did:key and
// a label. A device outside every circle this node holds is named by its
// did:key (`fabric status` on that device shows it).
func resolveDevice(client *daemon.Client, target string) (deviceDID, label string, err error) {
	if strings.HasPrefix(target, "did:key:") {
		if _, err := did.KeyFor(target); err != nil {
			return "", "", fmt.Errorf("%q: %w", target, err)
		}
		return target, target, nil
	}
	if client == nil {
		return "", "", fmt.Errorf("resolving %q needs this node's fabric identity and running daemon; give the device's did:key instead", target)
	}
	members, err := client.Members()
	if err != nil {
		return "", "", fmt.Errorf("resolving %q needs the running node daemon ('fabric up'), or give the device's did:key: %w", target, err)
	}
	var matches []daemon.MemberInfo
	for _, m := range members {
		if memberMatches(m, target) {
			matches = append(matches, m)
		}
	}
	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("no known device matches %q (see 'fabric status'); a device this node shares no circle with is named by its did:key", target)
	case 1:
	default:
		for _, m := range matches {
			fmt.Fprintf(os.Stderr, "  %s  %-16s %s\n", m.Fingerprint, m.Name, m.ID)
		}
		return "", "", fmt.Errorf("%q is ambiguous — %d devices match", target, len(matches))
	}
	m := matches[0]
	if m.Self {
		return "", "", fmt.Errorf("%q is this device — admit or revoke it from another owner device of the circle", m.Name)
	}
	return cert.DIDForKey(ed25519.PublicKey(m.DevicePub)), m.Name, nil
}

// circlePrefix resolves `-subnet` for a circle: auto derives from the DID,
// none is none, anything else must parse and must not be a range another
// circle on this node already uses.
func circlePrefix(root string, c *circle.Circle, subnet string) (string, error) {
	var prefix string
	switch subnet {
	case "none", "":
		return "", nil
	case "auto":
		prefix = circle.DefaultPrefix(c.Config.DID)
	default:
		p, err := netip.ParsePrefix(subnet)
		if err != nil {
			return "", fmt.Errorf("-subnet: %w", err)
		}
		prefix = p.Masked().String()
	}
	others, _ := circle.List(root)
	for _, o := range others {
		if o.Config.DID != c.Config.DID && o.Config.Prefix == prefix {
			return "", fmt.Errorf("overlay range %s is already circle %q's on this node — pick another with -subnet", prefix, o.Config.Name)
		}
	}
	return prefix, nil
}

// recordOnDisk adds the admission to the roster file directly — the CLI
// is the only writer when no daemon runs here.
func recordOnDisk(roster *circle.Roster, a *circle.Admission, now time.Time) error {
	nr, _, err := roster.Add(a.Stmt, now)
	if err != nil {
		return err
	}
	return nr.Save()
}

// deviceOverlayElsewhere reports the circle (name, or DID when unnamed
// here) in which the device already holds a live overlay address other
// than c, and that address — from the rosters of the circles this node
// holds and from the running daemon's peer view. "" when none is known.
func deviceOverlayElsewhere(root string, client *daemon.Client, c *circle.Circle, deviceDID string) (where, ip string) {
	now := time.Now()
	all, _ := circle.List(root)
	for _, other := range all {
		if other.Config.DID == c.Config.DID {
			continue
		}
		r, err := circle.OpenRoster(other, now)
		if err != nil {
			continue
		}
		if dev, ok := r.Live(deviceDID, now); ok {
			if v, err := cert.FromStatement(dev.Stmt); err == nil && v.Payload.Meta.IP != "" {
				return other.Config.Name, v.Payload.Meta.IP
			}
		}
	}
	if client != nil {
		if st, err := client.Status(); err == nil {
			for _, sp := range st.Peers {
				if sp.IP == "" || !sp.Member {
					continue
				}
				pid, err := peer.Decode(sp.ID)
				if err != nil {
					continue
				}
				if did, err := fabricnet.DeviceDID(pid); err != nil || did != deviceDID {
					continue
				}
				if !slices.Contains(sp.Circles, c.Config.DID) && len(sp.Circles) > 0 {
					return shortDID(sp.Circles[0]), sp.IP
				}
			}
		}
	}
	return "", ""
}

// listedGateHints returns this node's globally dialable addresses when it
// is a listed node, for a bundle's gate hints; a dark owner device cannot
// be dialed by a newcomer and offers none.
func listedGateHints(statePath string) []string {
	dir, err := state.Open(statePath)
	if err != nil {
		return nil
	}
	st, err := daemon.NewClient(dir).Status()
	if err != nil || st.Posture != "listed" {
		return nil
	}
	cands := st.ReachableAddrs
	if len(cands) == 0 {
		cands = st.Addrs
	}
	var out []string
	for _, a := range cands {
		if globalDialable(a) {
			out = append(out, a)
		}
	}
	return out
}

// cmdCircleAdmit signs a device into a circle without copying the key
// (task circle-member-devices, slice D): an owner device resolves the
// device's key, signs a admission with the role's verbs — `device`
// (sync, blob, subjects) or `gate` (`member, host` only: a public hop that
// reads nothing) — plus `tun` and an address in the circle's range when
// asked, records it in the circle's roster through the running daemon (so
// the circle learns the device before it connects), and writes a bundle
// the device installs with `fabric circle join` (or, on a fresh machine,
// `fabric join <bundle>`). The bundle carries no key.
func cmdCircleAdmit(args []string) error {
	fs := flag.NewFlagSet("circle admit", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle (required when the node holds several)")
	role := fs.String("role", circle.RoleDevice, "device (sync, blob, subjects) or gate (member, host only)")
	label := fs.String("name", "", "human label signed into the admission (default: the member's name)")
	tun := fs.Bool("tun", false, "also sign tun and an address in the circle's overlay range")
	validity := fs.Duration("validity", circle.DefaultValidity, "admission lifetime")
	out := fs.String("out", "", "bundle file to write for the device (required)")
	var gates stringList
	fs.Var(&gates, "gate", "gate hint for the device: a listed device of the circle, multiaddr with /p2p/ (repeatable; default: the circle's recorded hints plus this node's own when listed)")
	fs.Parse(args)
	if fs.NArg() != 1 || *out == "" {
		return fmt.Errorf("usage: fabric circle admit [-circle <name>] [-role device|gate] [-name <label>] [-tun] -out <file> <member-name | peer-id | fingerprint | did:key:…>")
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
	if !c.HasKey() {
		return fmt.Errorf("this device holds no key for circle %q — admit from an owner device", c.Config.Name)
	}
	verbs, err := circle.VerbsForRole(*role)
	if err != nil {
		return err
	}
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	var client *daemon.Client
	if _, err := dir.LoadDeviceKey(); err == nil {
		client = daemon.NewClient(dir)
	}
	deviceDID, memberName, err := resolveDevice(client, target)
	if err != nil {
		return err
	}
	devicePub, err := did.KeyFor(deviceDID)
	if err != nil {
		return err
	}
	if *label == "" && memberName != deviceDID {
		*label = memberName
	}
	meta := &statement.Meta{Name: *label}
	now := time.Now()

	// The owner's roster is what the address allocation goes by; the
	// daemon's copy is authoritative when it runs, the file otherwise.
	roster, err := circle.OpenRoster(c, now)
	if err != nil {
		return err
	}
	if *tun {
		if *role == circle.RoleGate {
			return errors.New("a gate never holds tun (memo §17: a public hop reads nothing and is no overlay endpoint)")
		}
		prefix := c.Config.Prefix
		cfg, _ := dir.LoadConfig()
		if cfg.CircleDID != "" && cfg.CircleDID != c.Config.DID {
			// One overlay per device until the per-circle bridge lands
			// (task slice H): the bridge has one route table and would
			// route between prefixes (Codex review, 2026-11-05).
			return fmt.Errorf("circle %q is not this node's first circle — an overlay in a second circle arrives with the per-circle bridge; admit without -tun for now", c.Config.Name)
		}
		// The same rule from the device's side: a device already holding
		// an address in another circle — known here from that circle's
		// roster or from the daemon's view — gets no second one (Codex
		// review, 2026-11-05: the owner-side check alone let an owner
		// hand a second overlay to a device of another circle).
		if where, ip := deviceOverlayElsewhere(root, client, c, deviceDID); where != "" {
			return fmt.Errorf("%s already holds overlay address %s in circle %s — one overlay per device until the per-circle bridge lands; admit without -tun", memberName, ip, where)
		}
		if prefix == "" && cfg.CircleDID == c.Config.DID {
			prefix = cfg.Subnet // the first circle minted before prefixes lived with the circle
		}
		if prefix == "" {
			return fmt.Errorf("circle %q has no overlay range — 'fabric circle init -subnet' set one at minting; this circle was minted without", c.Config.Name)
		}
		// Every address anyone holds in this circle: the roster file, this
		// device's own admission (admission or cert) and, when the daemon
		// runs, its union view including lapsed devices (the first circle's
		// addresses live in certs and the event log, not in devices.cbor;
		// Codex review, 2026-11-04).
		taken := roster.UsedIPs()
		if own, err := c.LoadAdmission(); err == nil && own.IP != "" {
			taken = append(taken, own.IP)
		}
		if own, err := dir.LoadCert(); err == nil && own != nil && own.Payload.Sub == c.Config.DID && own.Payload.Meta.IP != "" {
			taken = append(taken, own.Payload.Meta.IP)
		}
		var returning string
		if client != nil {
			if members, err := client.Members(); err == nil {
				for _, m := range members {
					if m.IP == "" {
						continue
					}
					if cert.DIDForKey(ed25519.PublicKey(m.DevicePub)) == deviceDID {
						returning = m.IP
						continue
					}
					taken = append(taken, m.IP)
				}
			}
		}
		inPrefix := func(ip string) bool {
			pfx, err := netip.ParsePrefix(prefix)
			if err != nil {
				return false
			}
			addr, err := netip.ParsePrefix(ip)
			if err != nil {
				return false
			}
			return pfx.Contains(addr.Addr())
		}
		// A returning device keeps its address — when that address is in
		// this circle's range (the union view also knows its addresses
		// elsewhere; Codex review, 2026-11-05).
		if dev, ok := roster.Device(deviceDID); ok && dev.Stmt.Payload.Meta != nil && inPrefix(dev.Stmt.Payload.Meta.IP) {
			meta.IP = dev.Stmt.Payload.Meta.IP
		} else if inPrefix(returning) {
			meta.IP = returning
		} else if meta.IP, err = tunbridge.NextFreeIP(prefix, taken); err != nil {
			return err
		}
		verbs = append(verbs, statement.VerbTun)
	}
	if len(gates) == 0 {
		gates = append(gates, c.Config.Gates...)
		for _, g := range listedGateHints(*statePath) {
			if !slices.Contains(gates, g) {
				gates = append(gates, g)
			}
		}
	}

	pass, err := passFor(c)
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	a, err := circle.AdmitWith(priv, nil, c.Config.DID, devicePub, now, *validity, verbs, meta)
	if err != nil {
		return err
	}
	bundle, err := circle.NewDeviceBundle(c, a, gates)
	if err != nil {
		return err
	}
	if err := circle.WriteBundle(*out, bundle); err != nil {
		return err
	}
	fmt.Printf("admitted %s into circle %q as a %s until %s\n", memberName, c.Config.Name, *role, a.Expiry().Format("2006-01-02"))
	if meta.IP != "" {
		fmt.Printf("  overlay address %s\n", meta.IP)
	}
	if len(gates) > 0 {
		fmt.Printf("  gates: %s\n", strings.Join(gates, " "))
	} else {
		fmt.Println("  no gate hints (this node is not listed and the circle records none): the device can only be dialed by devices that already know it — pass -gate")
	}
	raw, err := a.Marshal()
	if err != nil {
		return err
	}
	if client != nil {
		if _, err := client.CircleAdmit(raw); err == nil {
			fmt.Println("  the circle's roster knows the device now; devices online learn it at once, the rest by gossip")
		} else {
			if err := recordOnDisk(roster, a, now); err != nil {
				return err
			}
			fmt.Println("  recorded in the circle's roster on disk (no running daemon here: 'fabric up' gossips it)")
		}
	} else if err := recordOnDisk(roster, a, now); err != nil {
		return err
	}
	fmt.Printf("  bundle written to %s — move it privately to the device, then run there: fabric circle join %s (fresh machine: fabric join %s)\n", *out, filepath.Base(*out), filepath.Base(*out))
	return nil
}

// --- grants (step 4, slice G): a circle hands a bare key the right to a
// verb on a resource, no membership anywhere (memo §14: external operator's worker).

type grantRecord struct {
	ID      string   `json:"id"`
	DID     string   `json:"did"`
	Res     []string `json:"res"`
	Verbs   []string `json:"verbs"`
	Exp     int64    `json:"exp"`
	Issued  int64    `json:"issued"`
	Revoked int64    `json:"revoked,omitempty"`
	Label   string   `json:"label,omitempty"`
}

func grantsPath(c *circle.Circle) string { return filepath.Join(c.Path, "grants.json") }

func loadGrants(c *circle.Circle) ([]grantRecord, error) {
	raw, err := os.ReadFile(grantsPath(c))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []grantRecord
	return out, json.Unmarshal(raw, &out)
}

func saveGrants(c *circle.Circle, gs []grantRecord) error {
	raw, err := json.MarshalIndent(gs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(grantsPath(c), raw, 0o600)
}

func cmdCircleGrant(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fabric circle grant new|list|revoke")
	}
	switch args[0] {
	case "new":
		return cmdCircleGrantNew(args[1:])
	case "list":
		return cmdCircleGrantList(args[1:])
	case "revoke":
		return cmdCircleGrantRevoke(args[1:])
	}
	return fmt.Errorf("usage: fabric circle grant new|list|revoke")
}

// cmdCircleGrantNew mints a worker key and a root-signed grant for it in
// one key file: the file is the credential, hand it over privately.
func cmdCircleGrantNew(args []string) error {
	fs := flag.NewFlagSet("circle grant new", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle (required when the node holds several)")
	res := fs.String("res", "", "comma-separated subjects the grant covers (required)")
	verbs := fs.String("verbs", "claim", "comma-separated verbs: claim,publish,ack,read")
	exp := fs.Duration("exp", 90*24*time.Hour, "validity")
	label := fs.String("label", "", "a label for 'grant list'")
	out := fs.String("out", "", "key file to write (required; the grantee's only credential)")
	var gates stringList
	fs.Var(&gates, "gate", "listed gate multiaddr the grantee dials (repeatable; default: this node's announced addresses)")
	fs.Parse(args)
	if *res == "" || *out == "" {
		return fmt.Errorf("usage: fabric circle grant new -res <subjects> [-verbs claim] [-exp 2160h] -out worker.key [-gate addr]… [-circle name]")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(c.KeyPath()); err != nil {
		return fmt.Errorf("this device holds no key for circle %q — grant from an owner device", c.Config.Name)
	}
	resList, err := daemon.CleanSubjects(strings.Split(*res, ","))
	if err != nil {
		return err
	}
	verbList := daemon.CleanList(strings.Split(*verbs, ","))
	if len(gates) == 0 {
		// Only a listed node's own global addresses make sense as hints:
		// a dark owner device cannot be dialed by a stranger at all.
		if dir, err := state.Open(*statePath); err == nil {
			if st, err := daemon.NewClient(dir).Status(); err == nil {
				if st.Posture != "listed" {
					fmt.Fprintln(os.Stderr, "note: this node is not listed — pass -gate with the listed gate that hosts the subject")
				} else {
					cands := st.ReachableAddrs
					if len(cands) == 0 {
						cands = st.Addrs
					}
					for _, a := range cands {
						if globalDialable(a) {
							gates = append(gates, a)
						}
					}
				}
			}
		}
	}
	pass, err := passFor(c)
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	pub, workerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	var rs []statement.Resource
	for _, n := range resList {
		rs = append(rs, statement.Resource{Kind: statement.KindSubject, Name: n, Sub: c.Config.DID})
	}
	st, err := statement.Sign(priv, statement.Payload{
		Aud: did.ForKey(pub), Sub: c.Config.DID, Res: rs, Verbs: verbList,
		Nbf: now.Unix(), Exp: now.Add(*exp).Unix(), Iat: now.Unix(), Del: 0,
	}, nil)
	if err != nil {
		return err
	}
	wireBytes, err := st.Bytes()
	if err != nil {
		return err
	}
	if err := astral.WriteKeyFile(*out, astral.KeyFile{
		ID: st.IDHex(), DID: did.ForKey(pub), Circle: c.Config.DID, Res: resList, Verbs: verbList, Exp: now.Add(*exp).Unix(),
		Seed: base64.StdEncoding.EncodeToString(workerPriv.Seed()), Chain: base64.StdEncoding.EncodeToString(wireBytes),
		Gates: gates, Label: *label,
	}); err != nil {
		return err
	}
	gs, err := loadGrants(c)
	if err != nil {
		return err
	}
	if err := saveGrants(c, append(gs, grantRecord{ID: st.IDHex(), DID: did.ForKey(pub), Res: resList, Verbs: verbList, Exp: now.Add(*exp).Unix(), Issued: now.Unix(), Label: *label})); err != nil {
		return err
	}
	fmt.Printf("grant %s in circle %q to %s\n  %s on %s until %s\n  gates: %s\n  written to %s — the grantee's only credential; move it privately\n",
		st.IDHex()[:8], c.Config.Name, did.ForKey(pub), *verbs, *res, now.Add(*exp).Format("2006-01-02"), strings.Join(gates, " "), *out)
	if len(gates) == 0 {
		fmt.Println("  (no gates recorded: the grantee must pass -gate; the queue's host must be a listed gate)")
	}
	return nil
}

func cmdCircleGrantList(args []string) error {
	fs := flag.NewFlagSet("circle grant list", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle")
	fs.Parse(args)
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
	if err != nil {
		return err
	}
	gs, err := loadGrants(c)
	if err != nil {
		return err
	}
	if len(gs) == 0 {
		fmt.Printf("no grants issued by circle %q on this device\n", c.Config.Name)
		return nil
	}
	for _, g := range gs {
		state := "live"
		switch {
		case g.Revoked != 0:
			state = "REVOKED " + time.Unix(g.Revoked, 0).Format("2006-01-02")
		case time.Now().Unix() > g.Exp:
			state = "expired"
		}
		fmt.Printf("%s  %-10s %s on %s  to %s…  until %s  %s\n", g.ID[:8], g.Label, strings.Join(g.Verbs, ","), strings.Join(g.Res, ","), g.DID[len(g.DID)-8:], time.Unix(g.Exp, 0).Format("2006-01-02"), state)
	}
	return nil
}

// cmdCircleGrantRevoke signs a by-ID revocation with the circle root,
// stores it, and has the running daemon push it to connected members.
func cmdCircleGrantRevoke(args []string) error {
	fs := flag.NewFlagSet("circle grant revoke", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "which circle")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric circle grant revoke [-circle name] <id-prefix>")
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := pickCircle(root, *name)
	if err != nil {
		return err
	}
	gs, err := loadGrants(c)
	if err != nil {
		return err
	}
	i := -1
	for j, g := range gs {
		if strings.HasPrefix(g.ID, fs.Arg(0)) {
			if i >= 0 {
				return fmt.Errorf("%q matches several grants", fs.Arg(0))
			}
			i = j
		}
	}
	if i < 0 {
		return fmt.Errorf("no grant %q in circle %q", fs.Arg(0), c.Config.Name)
	}
	id, err := hex.DecodeString(gs[i].ID)
	if err != nil {
		return err
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
	r, err := circle.RevokeAs(priv, nil, c.Config.DID, statement.Target{ID: id}, now)
	if err != nil {
		return err
	}
	if _, err := c.AddRevocations(now, r); err != nil {
		return err
	}
	gs[i].Revoked = now.Unix()
	if err := saveGrants(c, gs); err != nil {
		return err
	}
	if dir, err := state.Open(*statePath); err == nil {
		if n, err := daemon.NewClient(dir).CircleRefresh(); err == nil {
			fmt.Printf("revoked grant %s; %d connected member(s) told, the rest learn on their next exchange\n", gs[i].ID[:8], n)
			return nil
		}
	}
	fmt.Printf("revoked grant %s (stored; members learn it on their next exchange with this node)\n", gs[i].ID[:8])
	return nil
}

// globalDialable keeps a multiaddr a stranger on the internet can dial: a
// /p2p/ component, no relay, and a global unicast IP (no loopback,
// private, link-local, CGNAT/overlay or ULA ranges).
func globalDialable(a string) bool {
	if !strings.Contains(a, "/p2p/") || strings.Contains(a, "p2p-circuit") {
		return false
	}
	m, err := ma.NewMultiaddr(a)
	if err != nil {
		return false
	}
	if strings.HasPrefix(a, "/dns") {
		return true
	}
	ip, err := manet.ToIP(m)
	if err != nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
		return false
	}
	if cgnat := netip.MustParsePrefix("100.64.0.0/10"); cgnat.Contains(addr) {
		return false
	}
	return true
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// shortDID is the tail of a did:key for display: the last eight characters.
func shortDID(did string) string {
	if len(did) > 8 {
		return did[len(did)-8:]
	}
	return did
}
