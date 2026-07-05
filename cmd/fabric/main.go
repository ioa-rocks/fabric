// fabric is the node CLI: init a namespace (master), join an existing one,
// run the daemon, and drive the admission queue.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aethera.dev/fabric/admission"
	"aethera.dev/fabric/cert"
	"aethera.dev/fabric/daemon"
	"aethera.dev/fabric/event"
	"aethera.dev/fabric/keystore"
	"aethera.dev/fabric/state"
	"aethera.dev/fabric/tunbridge"
	"aethera.dev/fabric/webui"

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
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "up":
		err = cmdUp(args)
	case "status":
		err = cmdStatus(args)
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
	case "ui":
		err = cmdUI(args)
	case "queue":
		err = cmdQueue(args)
	case "dns":
		err = cmdDNS(args)
	case "peer":
		err = cmdPeer(args)
	default:
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
  join     request admission to an existing namespace
  up       run the node daemon
  status   show node, membership, and connection state
  pending  list join requests awaiting approval (master)
  approve  approve a pending join request by fingerprint (master)
  deny     deny a pending join request by fingerprint (master)
  revoke   revoke a member by name, peer ID, or fingerprint (master)
  ui       serve the topology/admin web UI on localhost
  queue    queue on|off — run the admission queue on this node (lighthouse)
  dns      dns on|off; sudo dns setup — allow resolver self-registration
  peer     peer add <multiaddr> — add a bootstrap peer

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
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		d.Stop()
	}()
	return d.Run()
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

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	statePath := stateFlag(fs)
	name := fs.String("name", "", "human label for this device (required)")
	bootstrap := fs.String("bootstrap", "", "multiaddr of the queue host, incl. /p2p/<peer-id> (required)")
	listen := fs.String("listen", defaultListen, "listen multiaddrs, comma-separated")
	fs.Parse(args)
	if *name == "" || *bootstrap == "" {
		return fmt.Errorf("join: -name and -bootstrap are required")
	}
	listenAddrs, err := parseListen(*listen)
	if err != nil {
		return err
	}

	m, err := ma.NewMultiaddr(*bootstrap)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	target, err := peerpkg.AddrInfoFromP2pAddr(m)
	if err != nil {
		return fmt.Errorf("bootstrap must include /p2p/<peer-id>: %w", err)
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
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err = admission.Request(ctx, h, target.ID, req)
		cancel()
		switch {
		case err != nil:
			fmt.Print("!") // queue host unreachable; keep trying
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
		Bootstrap:    []string{*bootstrap},
	}); err != nil {
		return err
	}
	fmt.Printf("admitted to namespace %s as %q\n", resp.NamespaceDID, *name)
	fmt.Printf("start the node with: fabric up -state %s\n", dir.Path)
	return nil
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
		if m.Name == target ||
			(len(target) <= len(m.Fingerprint) && m.Fingerprint[:len(target)] == target) ||
			(len(target) >= 8 && len(target) <= len(m.ID) && m.ID[:len(target)] == target) {
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
	return http.ListenAndServe(*listen, webui.New(dir).Handler())
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
