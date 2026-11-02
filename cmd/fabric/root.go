package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/state"
)

// The mesh-root merge (statement-format task, decision 4): the namespace
// root becomes the home circle's key. `root merge` re-issues every member's
// cert under the circle key and gossips a root-moved event signed by the old
// root, so every node starts honouring the new root while the old one stays
// valid; `root retire` ends that once the roster shows everyone moved. New
// meshes are born merged (`fabric init` mints the circle around the root).
func cmdRoot(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric root status | root merge -circle <name> | root retire [-force] <did>")
	}
	switch args[0] {
	case "status":
		return cmdRootStatus(args[1:])
	case "merge":
		return cmdRootMerge(args[1:])
	case "retire":
		return cmdRootRetire(args[1:])
	}
	return fmt.Errorf("fabric root: unknown subcommand %q", args[0])
}

// certSub is the circle a roster member's cert was issued in.
func certSub(m daemon.MemberInfo) string {
	c, err := cert.Unmarshal(m.Cert)
	if err != nil {
		return ""
	}
	return c.Payload.Sub
}

func cmdRootStatus(args []string) error {
	fs := flag.NewFlagSet("root status", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	client := daemon.NewClient(dir)
	st, err := client.Status()
	if err != nil {
		return err
	}
	members, err := client.Members()
	if err != nil {
		return err
	}
	fmt.Printf("root      %s\n", st.NamespaceDID)
	for _, r := range st.HonouredRoots {
		fmt.Printf("honoured  %s (old root; retire it once every member has presented a cert under the new one)\n", r)
	}
	// What counts is the cert each device has presented in a handshake with
	// this daemon, not what the log says was issued to it: the merge put
	// every new cert into the log at once, so the roster alone would call
	// the move complete before any device adopted anything.
	confirmed, pending := 0, 0
	for _, m := range members {
		if m.Expired || m.Self {
			continue
		}
		switch {
		case m.PresentedSub == st.NamespaceDID:
			confirmed++
		case m.PresentedSub == "":
			pending++
			fmt.Printf("  %-16s unconfirmed — no handshake with this daemon since it started (issued under %s)\n", m.Name, shortDID(certSub(m)))
		default:
			pending++
			fmt.Printf("  %-16s still presents a cert under %s\n", m.Name, m.PresentedSub)
		}
	}
	if len(st.HonouredRoots) > 0 {
		if pending == 0 {
			fmt.Printf("%d member(s) confirmed on the current root by handshake — 'fabric root retire %s' completes the move\n", confirmed, st.HonouredRoots[0])
		} else {
			fmt.Printf("%d confirmed, %d pending; devices confirm by reconnecting or on their next handshake\n", confirmed, pending)
		}
	}
	return nil
}

func cmdRootMerge(args []string) error {
	fs := flag.NewFlagSet("root merge", flag.ExitOnError)
	statePath, vaultState := circleFlags(fs)
	name := fs.String("circle", "", "the circle whose key becomes the namespace root (required)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("usage: fabric root merge -circle <name>")
	}
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if !dir.IsMaster() {
		return fmt.Errorf("no namespace root key in %s — the merge runs on the master", dir.Path)
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	root, err := circleRoot(*statePath, *vaultState)
	if err != nil {
		return err
	}
	c, err := circle.ByName(root, *name)
	if err != nil {
		return err
	}
	if c.Config.DID == cfg.NamespaceDID {
		return fmt.Errorf("circle %q already is the namespace root (%s)", c.Config.Name, c.Config.DID)
	}
	if _, err := os.Stat(c.KeyPath()); err != nil {
		return fmt.Errorf("this device holds no key for circle %q", c.Config.Name)
	}
	client := daemon.NewClient(dir)
	members, err := client.Members()
	if err != nil {
		return fmt.Errorf("the merge needs the running node daemon ('fabric up'): %w", err)
	}

	var live []daemon.MemberInfo
	for _, m := range members {
		if m.Expired {
			fmt.Fprintf(os.Stderr, "skipping %q: cert expired — it re-joins under the new root\n", m.Name)
			continue
		}
		live = append(live, m)
	}
	fmt.Printf("moving namespace %s\n       onto circle %q %s\n", cfg.NamespaceDID, c.Config.Name, c.Config.DID)
	fmt.Printf("%d member cert(s) will be re-issued under the circle key; the old root stays honoured until 'fabric root retire'\n", len(live))

	pass, err := passFor(c)
	if err != nil {
		return err
	}
	newRoot, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	oldRoot, err := unlockRootKey(dir)
	if err != nil {
		return err
	}
	if cert.DIDForKey(oldRoot.Public().(ed25519.PublicKey)) != cfg.NamespaceDID {
		return fmt.Errorf("the root key container does not match namespace %s", cfg.NamespaceDID)
	}

	// 1. The old root hands over. Signed first and timestamped first, so
	//    every log replays it before the admissions it makes verifiable.
	now := time.Now()
	moved, err := event.NewRootMoved(oldRoot, c.Config.DID, now)
	if err != nil {
		return err
	}
	raw, err := moved.Marshal()
	if err != nil {
		return err
	}
	if err := client.Publish(raw); err != nil {
		return fmt.Errorf("publishing root-moved: %w", err)
	}
	fmt.Println("root-moved published: nodes now honour the circle key")

	// 2. Every live member gets its cert again, under the new root: same
	//    device, name, role, address and scope — only the issuer changes.
	//    Certs are valid from now; their events are stamped a second after
	//    the move so every log replays root-moved first.
	later := now.Add(time.Second)
	for _, m := range live {
		old, err := cert.Unmarshal(m.Cert)
		if err != nil {
			return fmt.Errorf("roster cert for %q: %w", m.Name, err)
		}
		fresh, err := cert.IssueAs(newRoot, nil, c.Config.DID, ed25519.PublicKey(m.DevicePub), old.Payload.Cmd, old.Payload.Meta, now, certValidity)
		if err != nil {
			return fmt.Errorf("re-issuing %q: %w", m.Name, err)
		}
		ev, err := event.NewAdded(newRoot, fresh, later)
		if err != nil {
			return err
		}
		raw, err := ev.Marshal()
		if err != nil {
			return err
		}
		if err := client.Publish(raw); err != nil {
			return fmt.Errorf("publishing %q's new cert: %w", m.Name, err)
		}
		fmt.Printf("re-issued: %q\n", m.Name)
	}

	// 3. The master signs with the circle key from now on: the root-key
	//    container becomes a copy of the circle's; the old one is kept.
	retired := dir.KeystorePath() + ".retired-" + shortDID(cfg.NamespaceDID)
	if err := os.Rename(dir.KeystorePath(), retired); err != nil {
		return fmt.Errorf("setting the old root aside: %w", err)
	}
	keyBytes, err := os.ReadFile(c.KeyPath())
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir.KeystorePath(), keyBytes, 0o600); err != nil {
		return fmt.Errorf("installing the circle key as the root key: %w", err)
	}
	fmt.Printf("root key container now holds circle %q's key (passphrase: the circle's); old root kept at %s\n", c.Config.Name, retired)
	fmt.Println()
	fmt.Println("next:")
	fmt.Printf("  1. update the _fabric DNS TXT record to the new DID ('fabric announce txt' prints it)\n")
	fmt.Printf("  2. watch 'fabric root status' until every member has presented a cert under %s\n", c.Config.DID)
	fmt.Printf("  3. 'fabric root retire %s' — after that, certs under the old root stop verifying everywhere\n", cfg.NamespaceDID)
	return nil
}

func cmdRootRetire(args []string) error {
	fs := flag.NewFlagSet("root retire", flag.ExitOnError)
	statePath := stateFlag(fs)
	force := fs.Bool("force", false, "retire even if live members still hold certs under that root (they are cut off and must re-join)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric root retire [-force] <did>")
	}
	old := fs.Arg(0)
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if !dir.IsMaster() {
		return fmt.Errorf("no namespace root key in %s — retirement runs on the master", dir.Path)
	}
	client := daemon.NewClient(dir)
	st, err := client.Status()
	if err != nil {
		return err
	}
	honoured := false
	for _, r := range st.HonouredRoots {
		honoured = honoured || r == old
	}
	if !honoured {
		return fmt.Errorf("%s is not an honoured old root here (current root %s; honoured: %s)", old, st.NamespaceDID, strings.Join(st.HonouredRoots, ", "))
	}
	members, err := client.Members()
	if err != nil {
		return err
	}
	// A device has moved when it has presented a cert under the new root,
	// not when the log holds one for it (see cmdRootStatus).
	var stranded []string
	for _, m := range members {
		if m.Expired || m.Self || m.PresentedSub == st.NamespaceDID {
			continue
		}
		if m.PresentedSub == "" {
			stranded = append(stranded, m.Name+" (no handshake since this daemon started)")
		} else {
			stranded = append(stranded, m.Name+" (still presents "+shortDID(m.PresentedSub)+")")
		}
	}
	if len(stranded) > 0 && !*force {
		return fmt.Errorf("%d live member(s) have not presented a cert under %s: %s — wait for them to reconnect with their new cert, or -force (they are cut off and must re-join)", len(stranded), st.NamespaceDID, strings.Join(stranded, ", "))
	}
	rootPriv, err := unlockRootKey(dir)
	if err != nil {
		return err
	}
	ev, err := event.NewRootRetired(rootPriv, old, time.Now())
	if err != nil {
		return err
	}
	raw, err := ev.Marshal()
	if err != nil {
		return err
	}
	if err := client.Publish(raw); err != nil {
		return err
	}
	fmt.Printf("retired: %s is no longer honoured; the namespace has one root again (%s)\n", old, st.NamespaceDID)
	if len(stranded) > 0 {
		fmt.Printf("cut off: %s\n", strings.Join(stranded, ", "))
	}
	return nil
}

func shortDID(did string) string {
	if len(did) > 8 {
		return did[len(did)-8:]
	}
	return did
}
