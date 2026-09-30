// fabric is the node CLI: init a namespace (master), join an existing one,
// run the daemon, drive the admission queue, and own the circle and
// buckets that ride the node (one noun per command group, each once).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ioa.rocks/fabric/admission"
	astralcli "ioa.rocks/fabric/astral/cli"
	astraldaemon "ioa.rocks/fabric/astral/daemon"
	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/state"
	"ioa.rocks/fabric/tunbridge"
	vaultcli "ioa.rocks/fabric/vault/cli"
	vaultdaemon "ioa.rocks/fabric/vault/daemon"
	vaultfusefs "ioa.rocks/fabric/vault/fusefs"
	vaultstore "ioa.rocks/fabric/vault/store"
	"ioa.rocks/fabric/webui"

	"github.com/libp2p/go-libp2p"
	"golang.org/x/term"

	peerpkg "github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	version      = "0.0.1"
	certValidity = cert.DefaultValidity // spec §5

	// Dual-stack, QUIC + TCP. QUIC gives a UDP underlay (no TCP-over-TCP
	// under the TUN bridge, and the path future hole-punching needs); TCP
	// stays as the fallback for UDP-hostile networks.
	defaultListen = "/ip4/0.0.0.0/udp/4517/quic-v1,/ip6/::/udp/4517/quic-v1,/ip4/0.0.0.0/tcp/4517,/ip6/::/tcp/4517"
)

// parseListen splits and validates a comma-separated multiaddr list.
func parseListen(s string) ([]string, error) {
	var addrs []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, err := ma.NewMultiaddr(a); err != nil {
			return nil, fmt.Errorf("listen addr %q: %w", a, err)
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no listen addresses")
	}
	return addrs, nil
}

func main() {
	// Busybox-style dispatch (ADR 0013, one binary): a "vault" symlink to
	// this binary is the bucket CLI.
	if filepath.Base(os.Args[0]) == "vault" {
		os.Exit(vaultcli.Main(os.Args[1:]))
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "bucket" {
		os.Exit(vaultcli.Main(args))
	}
	if cmd == "vault" {
		fmt.Fprintln(os.Stderr, "fabric: the vault command group is gone — the circle is 'fabric circle', its buckets are 'fabric bucket' (init → circle init, buckets → bucket list, sub/folder → bucket place)")
		os.Exit(2)
	}
	if cmd == "astral" {
		os.Exit(astralcli.Main(args))
	}
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "up":
		err = cmdUp(args)
	case "deploy":
		err = cmdDeploy(args)
	case "status":
		err = cmdStatus(args)
	case "graph":
		err = cmdGraph(args)
	case "join":
		err = cmdJoin(args)
	case "pending":
		err = cmdPending(args)
	case "approve":
		err = cmdApprove(args)
	case "deny":
		err = cmdDeny(args)
	case "revoke":
		err = cmdRevoke(args)
	case "renew":
		err = cmdRenew(args)
	case "ui":
		err = cmdUI(args)
	case "queue":
		err = cmdQueue(args)
	case "dns":
		err = cmdDNS(args)
	case "peer":
		err = cmdPeer(args)
	case "announce":
		err = cmdAnnounce(args)
	case "circle":
		err = cmdCircle(args)
	default:
		fmt.Fprintf(os.Stderr, "fabric: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fabric:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: fabric <command> [flags]

  init     create a new namespace on this device (it becomes the master)
  join     request admission to an existing namespace; the bootstrap is a
           full multiaddr or a bare hostname with a _fabric TXT record
           (fabric join -name laptop gate.example.com)
  up       run the node daemon
  status   show node, membership, and connection state
  graph    show the whole mesh's links; -json for machines
  pending  list join requests awaiting approval (master)
  approve  approve a pending join request by fingerprint (master)
  deny     deny a pending join request by fingerprint (master)
  revoke   revoke a member by name, peer ID, or fingerprint (master)
  renew    re-sign a member's cert with a fresh validity window (master);
           -expiring renews everything past half-life, this node included
  ui       serve the topology/admin web UI on localhost
  queue    queue on|off — run the admission queue on this node (lighthouse)
  dns      dns on|off; sudo dns setup — allow resolver self-registration
  peer     peer add <multiaddr> — add a bootstrap peer
  announce announce add <hostname|ip|multiaddr> — also advertise an address
           no local interface carries (cloud public IP / DNS name); ports,
           transports, and resolved IPs are derived automatically;
           announce txt — print the DNS TXT record for hostname joins
  deploy   deploy this x86-64 binary to ~/.local/bin on one or more SSH hosts
  circle   circle init -name <label> — mint this node's circle (the owner's
           user key: what buckets and, next, subjects belong to)
           circle export <file> / circle join <file> — a second device of
           the same owner; circle status — circle, buckets served, peers
  bucket   buckets of the circle ('fabric bucket -h'): create, list, place
           (full|cache|none|folder <dir>), mount, put/ls/get/rm, policy…;
           a "vault" symlink to this binary is the same group
  astral   hosted pub/sub subjects ('fabric astral -h'): publish, claim,
           registers — cast/claim/ack over the mesh

Every command accepts -state <dir> (default `+state.DefaultPath()+`).
`)
}

func stateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", state.DefaultPath(), "state directory")
}

// passphrase returns the keystore passphrase, from $FABRIC_PASSPHRASE or an
// interactive no-echo prompt.
func passphrase(prompt string) (string, error) {
	if p := os.Getenv("FABRIC_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no terminal for passphrase prompt; set FABRIC_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	statePath := stateFlag(fs)
	name := fs.String("name", "", "human label for this device (required)")
	listen := fs.String("listen", defaultListen, "listen multiaddrs, comma-separated")
	subnet := fs.String("subnet", "100.64.0.0/24", "overlay subnet for the TUN bridge (empty to disable overlay addressing)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("init: -name is required")
	}
	listenAddrs, err := parseListen(*listen)
	if err != nil {
		return err
	}
	var masterIP string
	if *subnet != "" {
		var err error
		if masterIP, err = tunbridge.NextFreeIP(*subnet, nil); err != nil {
			return fmt.Errorf("init: %w", err)
		}
	}

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if _, err := dir.LoadConfig(); err == nil {
		return fmt.Errorf("state dir %s is already initialized — remove %s/config.json (and the old cert.cbor/events.cbor/namespace.key.age) to re-init; the device key is kept", dir.Path, dir.Path)
	}

	priv, reused, err := dir.EnsureDeviceKey()
	if err != nil {
		return err
	}
	if reused {
		fmt.Println("reusing this device's existing identity key")
	}

	// Mint the namespace: the first device self-signs (spec §6).
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	rootPriv := ed25519.NewKeyFromSeed(seed)
	pass, err := passphrase("passphrase for the namespace root key: ")
	if err != nil {
		return err
	}
	if err := keystore.SaveSeed(dir.KeystorePath(), seed, pass); err != nil {
		return err
	}

	devicePubRaw, err := priv.GetPublic().Raw()
	if err != nil {
		return err
	}
	own, err := cert.Issue(rootPriv, ed25519.PublicKey(devicePubRaw), cert.CmdAdmin, cert.Meta{Name: *name, IP: masterIP}, time.Now(), certValidity)
	if err != nil {
		return err
	}
	if err := dir.SaveCert(own); err != nil {
		return err
	}
	// The master's own admission event: nodes that enter through a
	// lighthouse and never handshake the master directly still learn the
	// full roster (and the master's overlay IP) from gossip.
	selfAdded, err := event.NewAdded(rootPriv, own, time.Now())
	if err != nil {
		return err
	}
	if err := dir.SaveEvents([]*event.Event{selfAdded}); err != nil {
		return err
	}

	nsDID := cert.DIDForKey(rootPriv.Public().(ed25519.PublicKey))
	if err := dir.SaveConfig(state.Config{
		Name:         *name,
		ListenAddrs:  listenAddrs,
		NamespaceDID: nsDID,
		Subnet:       *subnet,
	}); err != nil {
		return err
	}

	fmt.Printf("namespace created: %s\n", nsDID)
	fmt.Printf("this device (%q) is the master and holds the root key\n", *name)
	if masterIP != "" {
		fmt.Printf("overlay subnet %s; this device is %s\n", *subnet, masterIP)
	}
	fmt.Printf("root-key container: %s — back it up and test the restore\n", dir.KeystorePath())
	fmt.Printf("start the node with: fabric up -state %s\n", dir.Path)
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	statePath := stateFlag(fs)
	noTun := fs.Bool("no-tun", false, "run without the TUN bridge for this run")
	vaultState := fs.String("vault-state", vaultstore.DefaultPath(), "vault store directory (buckets are served when the node has a circle)")
	noVault := fs.Bool("no-vault", false, "run without the vault subsystem for this run")
	astralState := fs.String("astral-state", astraldaemon.DefaultPath(), "astral state directory (the coordination plane; always on)")
	noAstral := fs.Bool("no-astral", false, "run without the astral subsystem for this run")
	fs.Parse(args)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	d, err := daemon.New(dir)
	if err != nil {
		return err
	}
	d.DisableTUN = *noTun

	// The vault subsystem (ADR 0013): activated only when the node has a
	// circle — a pure-connectivity node never touches it. Attach before
	// d.Run so handlers and the auth hook are in place for the first peer.
	// A pre-hoist circle still living in the store directory is adopted
	// into the node's state first (ADR 0017: the circle is fabric's).
	var vd *vaultdaemon.Daemon
	if !*noVault {
		circleDir := circle.Dir(*statePath)
		if did, err := circle.Migrate(circleDir, *vaultState); err != nil {
			return fmt.Errorf("adopting the circle from %s: %w", *vaultState, err)
		} else if did {
			log.Printf("circle adopted from %s into %s (the old copy is left in place, unused)", *vaultState, circleDir)
		}
		if circle.Exists(circleDir) {
			c, err := circle.Open(circleDir)
			if err != nil {
				return fmt.Errorf("vault subsystem: %w", err)
			}
			st, err := vaultstore.Open(*vaultState, c)
			if err != nil {
				return fmt.Errorf("vault subsystem: %w", err)
			}
			vd, err = vaultdaemon.New(st, d)
			if err != nil {
				return fmt.Errorf("vault subsystem: %w", err)
			}
			// Declared mounts are served by this process (ADR 0016); the
			// daemon package cannot construct the FUSE side itself.
			vd.Mounter = vaultfusefs.DaemonMounter{StatePath: *vaultState}
		}
	}

	// The astral subsystem (ADR 0015): the plane exists wherever fabric
	// runs, so it is on by default; attach after vault so its auth hook
	// chains onto vault's.
	var ad *astraldaemon.Daemon
	if !*noAstral {
		ad, err = astraldaemon.New(*astralState, d)
		if err != nil {
			return fmt.Errorf("astral subsystem: %w", err)
		}
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		d.Stop()
	}()

	vaultErr := make(chan error, 1)
	if vd != nil {
		go func() { vaultErr <- vd.Run() }()
	} else {
		vaultErr <- nil
	}
	astralErr := make(chan error, 1)
	if ad != nil {
		go func() { astralErr <- ad.Run() }()
	} else {
		astralErr <- nil
	}
	err = d.Run()
	if vd != nil {
		vd.Stop()
	}
	if ad != nil {
		ad.Stop()
	}
	if verr := <-vaultErr; verr != nil && err == nil {
		err = fmt.Errorf("vault subsystem: %w", verr)
	}
	if aerr := <-astralErr; aerr != nil && err == nil {
		err = fmt.Errorf("astral subsystem: %w", aerr)
	}
	return err
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	s, err := daemon.NewClient(dir).Status()
	if err != nil {
		return err
	}
	role := "member"
	if s.Master {
		role = "master"
	}
	if s.QueueHost && !s.Master {
		role += ", queue host"
	}
	fmt.Printf("%s (%s)  peer %s\n", s.Name, role, s.PeerID)
	fmt.Printf("namespace %s\n", s.NamespaceDID)
	if s.OverlayIP != "" {
		tun := "tun down (other transports still work)"
		if s.TUNActive {
			tun = "tun up (fabric0)"
			if s.DNSActive {
				tun += ", .fabric dns up"
			}
		}
		fmt.Printf("overlay %s — %s\n", s.OverlayIP, tun)
	}
	if s.Reachability != "" {
		fmt.Printf("nat %s", strings.ToLower(s.Reachability))
		if len(s.ReachableAddrs)+len(s.UnreachableAddrs) > 0 {
			fmt.Printf(" — per address:")
		}
		fmt.Println()
		for _, a := range s.ReachableAddrs {
			fmt.Printf("  reachable    %s\n", a)
		}
		for _, a := range s.UnreachableAddrs {
			fmt.Printf("  unreachable  %s\n", a)
		}
	}
	for _, a := range s.Addrs {
		fmt.Printf("  listen %s\n", a)
	}
	if len(s.Peers) == 0 {
		fmt.Println("no known peers")
		return nil
	}
	fmt.Println("peers:")
	for _, p := range s.Peers {
		conn := "offline"
		if p.Connected {
			conn = "connected"
		}
		member := "STRANGER"
		switch {
		case p.Revoked:
			member = "REVOKED"
		case p.Member:
			member = "member"
		}
		name := p.Name
		if name == "" {
			name = "?"
		}
		ip := p.IP
		if ip == "" {
			ip = "-"
		}
		fmt.Printf("  %-16s %-9s %-8s %-18s %s\n", name, conn, member, ip, p.ID)
	}
	return nil
}

// cmdGraph prints the aggregated mesh map — every live link any reachable
// member reports, with names resolved. -json emits the same for machines.
func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	statePath := stateFlag(fs)
	jsonOut := fs.Bool("json", false, "machine-readable output")
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
	links, err := client.Graph()
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"self": st.PeerID, "peers": st.Peers, "links": links})
	}

	names := map[string]string{st.PeerID: st.Name + " (this node)"}
	for _, p := range st.Peers {
		if p.Name != "" {
			names[p.ID] = p.Name
		}
	}
	name := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		return id[:8] + "…"
	}
	if len(links) == 0 {
		fmt.Println("no live links reported")
		return nil
	}
	for _, l := range links {
		rtt := "     ?"
		if l.RTTMillis > 0 {
			rtt = fmt.Sprintf("%6.1f ms", l.RTTMillis)
		}
		kind := l.Transport
		if l.Relayed {
			kind += " RELAYED"
		}
		fmt.Printf("  %-18s <-> %-18s %s  %s\n", name(l.A), name(l.B), rtt, kind)
	}
	return nil
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	statePath := stateFlag(fs)
	name := fs.String("name", "", "human label for this device (required)")
	bootstrap := fs.String("bootstrap", "", "queue host: full multiaddr incl. /p2p/<peer-id>, or bare host[:port] resolved via its _fabric TXT record")
	listen := fs.String("listen", defaultListen, "listen multiaddrs, comma-separated")
	fs.Parse(args)
	if *bootstrap == "" && fs.NArg() == 1 {
		*bootstrap = fs.Arg(0) // `fabric join -name x gate.example.com`
	}
	if *name == "" || *bootstrap == "" {
		return fmt.Errorf("join: -name and a bootstrap target are required")
	}
	listenAddrs, err := parseListen(*listen)
	if err != nil {
		return err
	}

	bootAddrs, expectNS, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	var target peerpkg.AddrInfo
	for _, a := range bootAddrs {
		m, err := ma.NewMultiaddr(a)
		if err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
		info, err := peerpkg.AddrInfoFromP2pAddr(m)
		if err != nil {
			return fmt.Errorf("bootstrap must include /p2p/<peer-id>: %w", err)
		}
		if target.ID == "" {
			target.ID = info.ID
		} else if info.ID != target.ID {
			return fmt.Errorf("bootstrap addresses disagree on the peer ID")
		}
		target.Addrs = append(target.Addrs, info.Addrs...)
	}

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if _, err := dir.LoadConfig(); err == nil {
		return fmt.Errorf("state dir %s already belongs to a namespace — to re-join a new one, remove %s/config.json (and the old cert.cbor/events.cbor) first; the device key is kept", dir.Path, dir.Path)
	}
	priv, reused, err := dir.EnsureDeviceKey()
	if err != nil {
		return err
	}
	if reused {
		fmt.Println("reusing this device's existing identity key")
	}
	devicePubRaw, err := priv.GetPublic().Raw()
	if err != nil {
		return err
	}

	// A plain client host: no gater needed, we are the stranger here.
	h, err := libp2p.New(libp2p.Identity(priv), libp2p.NoListenAddrs)
	if err != nil {
		return err
	}
	defer h.Close()
	h.Peerstore().AddAddrs(target.ID, target.Addrs, time.Hour)

	req := admission.JoinRequest{DevicePub: devicePubRaw, Name: *name, Version: version}
	fmt.Printf("this device: %q, key fingerprint %s\n", *name, admission.Fingerprint(devicePubRaw))
	fmt.Printf("compare this fingerprint on the approving device before approving.\n")
	fmt.Printf("waiting for approval")

	var resp *admission.JoinResponse
	lastErr := ""
	shownNS := false
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err = admission.Request(ctx, h, target.ID, req)
		cancel()
		// The joiner's side of the ceremony: the master's human compares
		// OUR fingerprint; we get shown the namespace we are about to
		// trust. A DNS-pinned namespace (ns= in the TXT record) verifies
		// itself; otherwise it's the human's to check.
		if err == nil && !shownNS && resp.NamespaceDID != "" {
			shownNS = true
			fmt.Printf("\nqueue host serves namespace %s\n", resp.NamespaceDID)
			switch {
			case expectNS == "":
				fmt.Println("verify this matches the namespace on the master (fabric status / UI header) before it approves.")
			case resp.NamespaceDID != expectNS:
				return fmt.Errorf("namespace mismatch: the _fabric DNS record promises %s — refusing to join", expectNS)
			default:
				fmt.Println("matches the _fabric DNS record — namespace pre-verified.")
			}
			fmt.Print("waiting for approval")
		}
		switch {
		case err != nil:
			// Say why, once per distinct reason — "protocol not supported"
			// means the target runs no admission queue (not master, no
			// `fabric queue on`); other errors are reachability.
			if msg := err.Error(); msg != lastErr {
				lastErr = msg
				fmt.Printf("\njoin attempt failed (will keep retrying): %v\n", err)
				if strings.Contains(msg, "protocols not supported") || strings.Contains(msg, "protocol not supported") {
					fmt.Println("hint: the bootstrap node does not accept join requests — point at the master, or run 'fabric queue on' there")
				}
				fmt.Print("waiting")
			}
			fmt.Print("!")
		case resp.Status == admission.StatusApproved:
			goto approved
		case resp.Status == admission.StatusDenied:
			fmt.Println()
			return fmt.Errorf("join request was denied")
		default:
			fmt.Print(".")
		}
		time.Sleep(3 * time.Second)
	}

approved:
	fmt.Println()
	if expectNS != "" && resp.NamespaceDID != expectNS {
		return fmt.Errorf("namespace mismatch: the _fabric DNS record promises %s but the cert came from %s — refusing to join", expectNS, resp.NamespaceDID)
	}
	c, err := cert.Unmarshal(resp.Cert)
	if err != nil {
		return fmt.Errorf("received cert: %w", err)
	}
	nsPub, err := cert.KeyForDID(resp.NamespaceDID)
	if err != nil {
		return fmt.Errorf("received namespace DID: %w", err)
	}
	if err := cert.Verify(c, nsPub, time.Now()); err != nil {
		return fmt.Errorf("received cert does not verify: %w", err)
	}
	devKey, err := c.DeviceKey()
	if err != nil {
		return err
	}
	if !devKey.Equal(ed25519.PublicKey(devicePubRaw)) {
		return fmt.Errorf("received cert is for a different device key")
	}

	if err := dir.SaveCert(c); err != nil {
		return err
	}
	if err := dir.SaveConfig(state.Config{
		Name:         *name,
		ListenAddrs:  listenAddrs,
		NamespaceDID: resp.NamespaceDID,
		Bootstrap:    bootAddrs,
	}); err != nil {
		return err
	}
	fmt.Printf("admitted to namespace %s as %q\n", resp.NamespaceDID, *name)
	fmt.Printf("start the node with: fabric up -state %s\n", dir.Path)
	return nil
}

// resolveBootstrap turns the join target into pinned bootstrap multiaddr
// strings. Two forms:
//
//   - a full multiaddr incl. /p2p/<peer-id> — used as-is;
//
//   - a bare host[:port] shortcut ("gate.example.com") — the peer-ID pin
//     then comes from a DNS TXT record at _fabric.<host>:
//
//     _fabric.gate.example.com. TXT "v=fabric1; peer=<peer-id>; ns=<did:key:…>"
//
//     (`fabric announce txt` on the lighthouse prints that line.) The
//     optional ns= pre-pins the namespace: the join hard-fails on any
//     mismatch instead of leaning on the human fingerprint check.
func resolveBootstrap(arg string) (addrs []string, expectNS string, err error) {
	if strings.HasPrefix(arg, "/") {
		return []string{arg}, "", nil // full multiaddr; validated by the caller
	}
	host, port := arg, "4517"
	if h, p, ok := strings.Cut(arg, ":"); ok {
		host, port = h, p
	}
	txts, err := net.LookupTXT("_fabric." + host)
	peerID, ns := parseFabricTXT(txts)
	if err != nil || peerID == "" {
		if err == nil {
			err = fmt.Errorf("no peer= entry")
		}
		return nil, "", fmt.Errorf(`cannot resolve %q as a join shortcut: _fabric.%s TXT lookup: %v
publish this DNS record (printed by 'fabric announce txt' on the queue host):
  _fabric.%s. TXT "v=fabric1; peer=<peer-id>; ns=<namespace-did>"
or pass a full multiaddr including /p2p/<peer-id>`, arg, host, err, host)
	}
	comp := "/dns4/" + host
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			comp = "/ip4/" + host
		} else {
			comp = "/ip6/" + host
		}
	}
	return []string{
		fmt.Sprintf("%s/udp/%s/quic-v1/p2p/%s", comp, port, peerID),
		fmt.Sprintf("%s/tcp/%s/p2p/%s", comp, port, peerID),
	}, ns, nil
}

// parseFabricTXT picks the peer-ID and optional namespace DID out of
// _fabric TXT strings ("v=fabric1; peer=<id>; ns=<did>").
func parseFabricTXT(txts []string) (peerID, ns string) {
	for _, txt := range txts {
		var p, n string
		for _, f := range strings.FieldsFunc(txt, func(r rune) bool { return r == ';' || r == ' ' }) {
			k, v, ok := strings.Cut(strings.TrimSpace(f), "=")
			if !ok {
				continue
			}
			switch k {
			case "peer":
				p = v
			case "ns":
				n = v
			}
		}
		if p != "" {
			return p, n
		}
	}
	return "", ""
}

func cmdPending(args []string) error {
	fs := flag.NewFlagSet("pending", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	pending, err := daemon.NewClient(dir).Pending()
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("no pending join requests")
		return nil
	}
	for _, p := range pending {
		fmt.Printf("%s  %-9s %-16s requested %s\n", p.Fingerprint, p.Status, p.Name, p.ReceivedAt.Format(time.RFC3339))
	}
	return nil
}

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric approve <fingerprint>")
	}
	fp := fs.Arg(0)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if !dir.IsMaster() {
		return fmt.Errorf("no namespace root key in %s — approvals happen on the master", dir.Path)
	}
	client := daemon.NewClient(dir)
	pending, err := client.Pending()
	if err != nil {
		return err
	}
	var match *admission.PendingInfo
	for i := range pending {
		if len(fp) <= len(pending[i].Fingerprint) && pending[i].Fingerprint[:len(fp)] == fp {
			if match != nil {
				return fmt.Errorf("fingerprint prefix %q is ambiguous", fp)
			}
			match = &pending[i]
		}
	}
	if match == nil {
		return fmt.Errorf("no pending request matches %q", fp)
	}
	if match.Status != admission.StatusPending {
		return fmt.Errorf("request %s is already %s", match.Fingerprint, match.Status)
	}

	fmt.Printf("approving %q, key fingerprint %s\n", match.Name, match.Fingerprint)
	fmt.Printf("confirm this fingerprint matches the one shown on the joining device.\n")

	// Signing happens here, in the CLI process — the daemon never holds the
	// root key (spec §1/§3).
	members, err := client.Members()
	if err != nil {
		return err
	}
	ip, err := daemon.AllocateOverlayIP(dir, members)
	if err != nil {
		return err
	}
	if ip != "" {
		fmt.Printf("assigning overlay address %s\n", ip)
	}

	rootPriv, err := unlockRootKey(dir)
	if err != nil {
		return err
	}
	now := time.Now()
	c, err := cert.Issue(rootPriv, ed25519.PublicKey(match.DevicePub), cert.CmdMember, cert.Meta{Name: match.Name, IP: ip}, now, certValidity)
	if err != nil {
		return err
	}
	signed, err := c.Marshal()
	if err != nil {
		return err
	}
	// The admission is also a signed membership event, gossiped to every
	// node (spec §5 admission transparency).
	ev, err := event.NewAdded(rootPriv, c, now)
	if err != nil {
		return err
	}
	signedEv, err := ev.Marshal()
	if err != nil {
		return err
	}
	if err := client.Approve(match.Fingerprint, signed, signedEv); err != nil {
		return err
	}
	fmt.Printf("approved: %q is now a member (cert valid %s)\n", match.Name, certValidity)
	return nil
}

// unlockRootKey prompts for the passphrase and loads the namespace root key.
// Signing always happens in the CLI process; the daemon never sees the key.
func unlockRootKey(dir state.Dir) (ed25519.PrivateKey, error) {
	pass, err := passphrase("namespace root key passphrase: ")
	if err != nil {
		return nil, err
	}
	seed, err := keystore.LoadSeed(dir.KeystorePath(), pass)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric revoke <name | peer-id | fingerprint>")
	}
	target := fs.Arg(0)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if !dir.IsMaster() {
		return fmt.Errorf("no namespace root key in %s — revocation happens on the master", dir.Path)
	}
	client := daemon.NewClient(dir)
	members, err := client.Members()
	if err != nil {
		return err
	}

	var matches []daemon.MemberInfo
	for _, m := range members {
		if m.Self {
			continue // retiring the master is a bigger operation than a one-liner
		}
		if memberMatches(m, target) {
			matches = append(matches, m)
		}
	}
	switch len(matches) {
	case 0:
		return fmt.Errorf("no member matches %q (see 'fabric status' for the roster)", target)
	case 1:
	default:
		for _, m := range matches {
			fmt.Fprintf(os.Stderr, "  %s  %-16s %s\n", m.Fingerprint, m.Name, m.ID)
		}
		return fmt.Errorf("%q is ambiguous — %d members match", target, len(matches))
	}
	m := matches[0]

	fmt.Printf("revoking %q, key fingerprint %s\n", m.Name, m.Fingerprint)
	fmt.Printf("peer %s (cert would expire %s)\n", m.ID, m.Expiry.Format(time.RFC3339))
	fmt.Printf("this cuts the device off immediately; re-admission requires a new join\n")

	rootPriv, err := unlockRootKey(dir)
	if err != nil {
		return err
	}
	ev, err := event.NewRevoked(rootPriv, ed25519.PublicKey(m.DevicePub), time.Now())
	if err != nil {
		return err
	}
	signedEv, err := ev.Marshal()
	if err != nil {
		return err
	}
	if err := client.Revoke(signedEv); err != nil {
		return err
	}
	fmt.Printf("revoked: %q is out of the namespace\n", m.Name)
	return nil
}

func memberMatches(m daemon.MemberInfo, target string) bool {
	return m.Name == target ||
		(len(target) <= len(m.Fingerprint) && m.Fingerprint[:len(target)] == target) ||
		(len(target) >= 8 && len(target) <= len(m.ID) && m.ID[:len(target)] == target)
}

// cmdRenew re-signs membership certs with a fresh validity window (spec §5).
// The payload is preserved verbatim — same device key, name, role, overlay
// IP — so renewal never renumbers a node. The re-signed cert travels as a
// MemberAdded event; stores keep the later expiry and the renewed node
// adopts its own cert live.
func cmdRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	statePath := stateFlag(fs)
	expiring := fs.Bool("expiring", false, "renew every cert past half-life (this node's included)")
	fs.Parse(args)
	if *expiring == (fs.NArg() == 1) {
		return fmt.Errorf("usage: fabric renew <name | peer-id | fingerprint>  |  fabric renew -expiring")
	}

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if !dir.IsMaster() {
		return fmt.Errorf("no namespace root key in %s — renewal happens on the master", dir.Path)
	}
	client := daemon.NewClient(dir)
	members, err := client.Members()
	if err != nil {
		return err
	}

	var targets []daemon.MemberInfo
	if *expiring {
		for _, m := range members {
			if time.Until(m.Expiry) < cert.RenewBelow {
				targets = append(targets, m)
			}
		}
		if len(targets) == 0 {
			fmt.Printf("nothing to renew: every cert has more than %d days left\n", int(cert.RenewBelow.Hours()/24))
			return nil
		}
	} else {
		target := fs.Arg(0)
		var matches []daemon.MemberInfo
		for _, m := range members {
			if memberMatches(m, target) {
				matches = append(matches, m)
			}
		}
		switch len(matches) {
		case 0:
			return fmt.Errorf("no member matches %q (see 'fabric status' for the roster)", target)
		case 1:
			targets = matches
		default:
			for _, m := range matches {
				fmt.Fprintf(os.Stderr, "  %s  %-16s %s\n", m.Fingerprint, m.Name, m.ID)
			}
			return fmt.Errorf("%q is ambiguous — %d members match", target, len(matches))
		}
	}

	for _, m := range targets {
		self := ""
		if m.Self {
			self = " (this node)"
		}
		fmt.Printf("renewing %q%s — currently expires %s\n", m.Name, self, m.Expiry.Format(time.RFC3339))
	}
	rootPriv, err := unlockRootKey(dir)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, m := range targets {
		old, err := cert.Unmarshal(m.Cert)
		if err != nil {
			return fmt.Errorf("roster cert for %q: %w", m.Name, err)
		}
		renewed, err := cert.Renew(rootPriv, old, now, cert.DefaultValidity)
		if err != nil {
			return fmt.Errorf("renewing %q: %w", m.Name, err)
		}
		ev, err := event.NewAdded(rootPriv, renewed, now)
		if err != nil {
			return err
		}
		signedEv, err := ev.Marshal()
		if err != nil {
			return err
		}
		if err := client.Renew(signedEv); err != nil {
			return fmt.Errorf("delivering renewal for %q: %w", m.Name, err)
		}
		fmt.Printf("renewed: %q now expires %s\n", m.Name, renewed.Expiry().Format(time.RFC3339))
	}
	return nil
}

func cmdDeny(args []string) error {
	fs := flag.NewFlagSet("deny", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric deny <fingerprint>")
	}
	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if err := daemon.NewClient(dir).Deny(fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("denied")
	return nil
}

func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	statePath := stateFlag(fs)
	listen := fs.String("listen", "127.0.0.1:4518", "listen address; keep it on localhost — the UI has no auth of its own")
	vaultState := fs.String("vault-state", vaultstore.DefaultPath(), "vault store directory (vault card lights up when its daemon runs)")
	astralState := fs.String("astral-state", astraldaemon.DefaultPath(), "astral state directory (coordination card lights up when its daemon runs)")
	fs.Parse(args)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	if _, err := daemon.NewClient(dir).Status(); err != nil {
		return fmt.Errorf("daemon check: %w", err)
	}
	role := "read-only (no root key here)"
	if dir.IsMaster() {
		role = "master — approvals and revocations enabled"
	}
	fmt.Printf("topology UI: http://%s  (%s)\n", *listen, role)
	return http.ListenAndServe(*listen, webui.New(dir, *vaultState, *astralState).Handler())
}

func cmdQueue(args []string) error {
	if len(args) < 1 || (args[0] != "on" && args[0] != "off") {
		return fmt.Errorf("usage: fabric queue on|off [-state <dir>]")
	}
	fs := flag.NewFlagSet("queue", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args[1:])

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	cfg.QueueHost = args[0] == "on"
	if err := dir.SaveConfig(cfg); err != nil {
		return err
	}
	if cfg.QueueHost {
		fmt.Println("admission queue enabled — this node accepts join requests (lighthouse role); restart the daemon to apply")
		fmt.Println("joiners bootstrap against this node's address; the master approves from anywhere in the mesh")
	} else {
		fmt.Println("admission queue disabled; restart the daemon to apply")
	}
	return nil
}

// polkitRulePath and the rule let the unprivileged daemon register its
// .fabric resolver with systemd-resolved on every start, silently.
const polkitRulePath = "/etc/polkit-1/rules.d/50-fabric-dns.rules"

const polkitRuleTemplate = `// Installed by 'sudo fabric dns setup'.
// Lets the fabric daemon (running as %[1]q) point systemd-resolved's
// ~fabric routing domain at its own .fabric resolver.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.resolve1.set-dns-servers" ||
         action.id == "org.freedesktop.resolve1.set-domains") &&
        subject.user == %[1]q) {
        return polkit.Result.YES;
    }
});
`

func cmdDNS(args []string) error {
	if len(args) >= 1 && args[0] == "setup" {
		return dnsSetup(args[1:])
	}
	if len(args) < 1 || (args[0] != "on" && args[0] != "off") {
		return fmt.Errorf("usage: fabric dns on|off  |  sudo fabric dns setup")
	}
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args[1:])

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	if args[0] == "off" {
		cfg.DNS = "off"
	} else {
		cfg.DNS = ""
	}
	if err := dir.SaveConfig(cfg); err != nil {
		return err
	}
	if cfg.DNS == "off" {
		fmt.Println(".fabric resolver disabled; restart the daemon to apply")
	} else {
		fmt.Println(".fabric resolver enabled (serves whenever the TUN bridge is up); restart the daemon to apply")
	}
	return nil
}

// dnsSetup installs the polkit rule (one sudo moment, survives reboots) and
// registers the resolver right away if the TUN device is already up.
func dnsSetup(args []string) error {
	fs := flag.NewFlagSet("dns setup", flag.ExitOnError)
	user := fs.String("user", os.Getenv("SUDO_USER"), "user the fabric daemon runs as")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return fmt.Errorf("dns setup writes %s — run it as: sudo fabric dns setup", polkitRulePath)
	}
	if *user == "" || *user == "root" {
		return fmt.Errorf("cannot determine the daemon user; pass -user <name>")
	}
	rule := fmt.Sprintf(polkitRuleTemplate, *user)
	if err := os.WriteFile(polkitRulePath, []byte(rule), 0o644); err != nil {
		return err
	}
	fmt.Printf("installed %s for user %q — the daemon can now register its resolver on every start\n", polkitRulePath, *user)

	// If fabric0 is already up, register now so no daemon restart is needed.
	if ifc, err := net.InterfaceByName("fabric0"); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					if exec.Command("resolvectl", "dns", "fabric0", ipn.IP.String()).Run() == nil &&
						exec.Command("resolvectl", "domain", "fabric0", "~fabric").Run() == nil {
						fmt.Printf("registered ~fabric via %s with systemd-resolved\n", ipn.IP)
					}
					break
				}
			}
		}
	}
	return nil
}

func cmdPeer(args []string) error {
	if len(args) < 2 || args[0] != "add" {
		return fmt.Errorf("usage: fabric peer add <multiaddr>")
	}
	fs := flag.NewFlagSet("peer add", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args[1:])
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric peer add <multiaddr>")
	}
	addr := fs.Arg(0)
	if _, err := ma.NewMultiaddr(addr); err != nil {
		return fmt.Errorf("multiaddr: %w", err)
	}

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	for _, existing := range cfg.Bootstrap {
		if existing == addr {
			fmt.Println("peer already configured")
			return nil
		}
	}
	cfg.Bootstrap = append(cfg.Bootstrap, addr)
	if err := dir.SaveConfig(cfg); err != nil {
		return err
	}
	fmt.Println("peer added; the daemon picks it up on restart")
	return nil
}

func cmdAnnounce(args []string) error {
	if len(args) >= 1 && args[0] == "txt" {
		return cmdAnnounceTXT(args[1:])
	}
	if len(args) < 2 || args[0] != "add" {
		return fmt.Errorf("usage: fabric announce add <hostname|ip|multiaddr> | fabric announce txt")
	}
	fs := flag.NewFlagSet("announce add", flag.ExitOnError)
	statePath := stateFlag(fs)
	force := fs.Bool("force", false, "add even when the address verifiably points at a different node")
	fs.Parse(args[1:])
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: fabric announce add [-force] <hostname|ip|multiaddr>")
	}
	entry := fs.Arg(0)
	// Operator-friendly forms: a bare DNS name ("gate.example.com"), a bare
	// IP, or a full multiaddr as the escape hatch. The daemon derives
	// ports/transports from its listen config and resolves names into IP
	// literals itself (daemon/announce.go).
	if daemon.AnnounceKind(entry) == "host" {
		if strings.ContainsAny(entry, "/: \t") || entry == "" {
			return fmt.Errorf("%q is not a hostname, IP, or multiaddr", entry)
		}
	}

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	for _, existing := range cfg.AnnounceAddrs {
		if existing == entry {
			fmt.Println("announce entry already configured")
			return nil
		}
	}

	// Guardrail against announcing someone else's address: dial the
	// expanded addresses expecting this node's own identity. A verified
	// mismatch refuses (that record would gossip to every member); mere
	// silence only warns — the daemon may not be running yet, the
	// provider firewall may still be closed, or the NAT refuses hairpin.
	priv, err := dir.LoadDeviceKey()
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	self, err := peerpkg.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	verified := false
	switch outcome, detail := daemon.VerifyAnnounce(context.Background(), entry, cfg.ListenAddrs, self); outcome {
	case daemon.VerifyOK:
		verified = true
	case daemon.VerifyMismatch:
		if !*force {
			return fmt.Errorf("%s does not route back to this node (%s) — check the DNS record / IP, or -force to add anyway", entry, detail)
		}
		fmt.Printf("warning: %s (-force, adding anyway)\n", detail)
	case daemon.VerifyUnreachable:
		fmt.Printf("note: could not verify %s routes back here (%s) — daemon not running, port not open yet, or hairpin unsupported; adding anyway\n", entry, detail)
	}

	cfg.AnnounceAddrs = append(cfg.AnnounceAddrs, entry)
	if err := dir.SaveConfig(cfg); err != nil {
		return err
	}
	if verified {
		fmt.Printf("verified: %s routes back to this node\n", entry)
	}
	fmt.Printf("announcing %s — the daemon will advertise:\n", entry)
	for _, m := range daemon.ExpandAnnounce([]string{entry}, cfg.ListenAddrs) {
		fmt.Printf("  %s\n", m)
	}
	if daemon.AnnounceKind(entry) == "host" {
		fmt.Println("(resolved addresses refresh automatically while the daemon runs)")
	}
	fmt.Println("restart the daemon to apply")
	return nil
}

// cmdAnnounceTXT prints the DNS TXT record that makes this node joinable
// by bare hostname (`fabric join <host>` — see resolveBootstrap).
func cmdAnnounceTXT(args []string) error {
	fs := flag.NewFlagSet("announce txt", flag.ExitOnError)
	statePath := stateFlag(fs)
	fs.Parse(args)

	dir, err := state.Open(*statePath)
	if err != nil {
		return err
	}
	cfg, err := dir.LoadConfig()
	if err != nil {
		return err
	}
	priv, err := dir.LoadDeviceKey()
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	pid, err := peerpkg.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}
	host := "<this-node's-dns-name>"
	for _, s := range cfg.AnnounceAddrs {
		if daemon.AnnounceKind(s) == "host" {
			host = s
			break
		}
		if m, err := ma.NewMultiaddr(s); err == nil {
			for _, p := range []int{ma.P_DNS4, ma.P_DNS6, ma.P_DNS} {
				if v, err := m.ValueForProtocol(p); err == nil && v != "" {
					host = v
					break
				}
			}
		}
		if host != "<this-node's-dns-name>" {
			break
		}
	}
	fmt.Printf("publish this DNS record to enable 'fabric join %s':\n", host)
	fmt.Printf("_fabric.%s. 300 IN TXT \"v=fabric1; peer=%s; ns=%s\"\n", host, pid, cfg.NamespaceDID)
	return nil
}
