// Package state persists a node's identity and configuration in a state
// directory (default ~/.config/fabric):
//
//	config.json        — name, listen addrs, circle DID, bootstrap peers
//	device.key         — libp2p ed25519 identity (protobuf), 0600
//	cert.cbor          — this node's membership certificate
//	events.cbor        — membership-event log (admissions, revocations)
//	records.cbor       — cached signed peer address records (restart warm-up)
//	namespace.key.age  — root key seed, master only (see keystore)
//	control.sock       — daemon control socket, runtime only
package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/event"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
)

type Config struct {
	Name        string   `json:"name"`
	ListenAddrs []string `json:"listen_addrs"`
	CircleDID   string   `json:"namespace_did"` // the home circle's DID: the root certs verify against
	Bootstrap   []string `json:"bootstrap"`     // multiaddrs including /p2p/<peer-id>; operator-configured (join, peer add): the lighthouses this node trusts as NAT oracles
	// DiscoveredBootstrap are lighthouse addresses pinned from what connected
	// members advertised (daemon.pinQueueHosts): dialed like Bootstrap for
	// recovery, but not trusted for anything — a member can advertise a
	// protocol on its own.
	DiscoveredBootstrap []string `json:"discovered_bootstrap,omitempty"`
	Subnet              string   `json:"subnet,omitempty"`     // overlay CIDR; master only (allocation)
	TUN                 string   `json:"tun,omitempty"`        // "" = auto (try, fall back), "off"
	QueueHost           bool     `json:"queue_host,omitempty"` // run the admission queue (lighthouse role)
	// Listed opens the connection gater to inbound peers this node holds
	// no cert for (they still have to authenticate). Off = dark: unknown
	// peers are refused before anything above the transport runs. Queue
	// hosts are listed regardless, since joiners must reach them.
	Listed bool   `json:"listed,omitempty"`
	DNS    string `json:"dns,omitempty"` // "" = serve .fabric when TUN is up, "off"
	// AnnounceAddrs are advertised in addition to the interface-derived
	// addresses — for reachable addresses no local interface carries, e.g.
	// a cloud instance's 1:1-NAT'd public IP or DNS name. Entries may be a
	// bare hostname, a bare IP, or a full multiaddr; the daemon expands
	// them (ports/transports from the listen config, hostnames resolved
	// into IP literals and refreshed) — see daemon/announce.go. They ride
	// the signed peer record like any discovered address.
	AnnounceAddrs []string `json:"announce_addrs,omitempty"`
}

type Dir struct{ Path string }

// DefaultPath returns ~/.config/fabric (or the OS equivalent).
func DefaultPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "fabric")
}

func Open(path string) (Dir, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return Dir{}, err
	}
	return Dir{Path: path}, nil
}

func (d Dir) configPath() string    { return filepath.Join(d.Path, "config.json") }
func (d Dir) deviceKeyPath() string { return filepath.Join(d.Path, "device.key") }
func (d Dir) certPath() string      { return filepath.Join(d.Path, "cert.cbor") }
func (d Dir) eventsPath() string    { return filepath.Join(d.Path, "events.cbor") }
func (d Dir) recordsPath() string   { return filepath.Join(d.Path, "records.cbor") }

// KeystorePath is where the master's root key seed lives.
func (d Dir) KeystorePath() string { return filepath.Join(d.Path, "namespace.key.age") }

// ControlSocketPath is the daemon's local control endpoint. Unix socket
// paths are capped at ~108 bytes (sun_path); for deep state dirs we fall
// back to a deterministic short path in the temp dir, derived from the
// state dir so daemon and CLI agree without coordination.
func (d Dir) ControlSocketPath() string {
	p := filepath.Join(d.Path, "control.sock")
	if len(p) < 100 {
		return p
	}
	abs, err := filepath.Abs(d.Path)
	if err != nil {
		abs = d.Path
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(os.TempDir(), fmt.Sprintf("fabric-%s.sock", hex.EncodeToString(sum[:6])))
}

// IsMaster reports whether this state dir holds the root key seed.
func (d Dir) IsMaster() bool {
	_, err := os.Stat(d.KeystorePath())
	return err == nil
}

func (d Dir) SaveConfig(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.configPath(), append(data, '\n'), 0o600)
}

func (d Dir) LoadConfig() (Config, error) {
	data, err := os.ReadFile(d.configPath())
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", d.configPath(), err)
	}
	return c, nil
}

// EnsureDeviceKey returns this node's libp2p identity, generating and
// persisting one on first use. An existing key is never overwritten — a
// device keeps its identity across circles (re-join after a circle
// re-init reuses it; only membership is circle-specific). reused reports
// whether a key was already there.
func (d Dir) EnsureDeviceKey() (priv crypto.PrivKey, reused bool, err error) {
	if data, err := os.ReadFile(d.deviceKeyPath()); err == nil {
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			return nil, false, fmt.Errorf("existing device key is unreadable: %w", err)
		}
		return priv, true, nil
	}
	priv, _, err = crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(d.deviceKeyPath(), data, 0o600); err != nil {
		return nil, false, err
	}
	return priv, false, nil
}

func (d Dir) LoadDeviceKey() (crypto.PrivKey, error) {
	data, err := os.ReadFile(d.deviceKeyPath())
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPrivateKey(data)
}

func (d Dir) SaveCert(c *cert.Cert) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(d.certPath(), data, 0o600)
}

// SaveEvents persists the membership-event log.
func (d Dir) SaveEvents(evs []*event.Event) error {
	data, err := cbor.Marshal(evs)
	if err != nil {
		return err
	}
	return os.WriteFile(d.eventsPath(), data, 0o600)
}

// SaveRecords persists gossiped signed address-record envelopes, so a
// restarted node can dial members straight away instead of waiting to
// re-learn WHERE everyone is. The envelopes are signed by their subjects;
// staleness is bounded by the gossip TTL applied when they are re-consumed.
func (d Dir) SaveRecords(recs [][]byte) error {
	data, err := cbor.Marshal(recs)
	if err != nil {
		return err
	}
	return os.WriteFile(d.recordsPath(), data, 0o600)
}

// LoadRecords returns (nil, nil) when no record cache exists yet. Records
// are untrusted until their envelope signatures verify on consumption.
func (d Dir) LoadRecords() ([][]byte, error) {
	data, err := os.ReadFile(d.recordsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs [][]byte
	if err := cbor.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", d.recordsPath(), err)
	}
	return recs, nil
}

// LoadEvents returns (nil, nil) when no event log exists yet. Events are
// untrusted until they pass verification into an event.Log.
func (d Dir) LoadEvents() ([]*event.Event, error) {
	data, err := os.ReadFile(d.eventsPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var evs []*event.Event
	if err := cbor.Unmarshal(data, &evs); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", d.eventsPath(), err)
	}
	return evs, nil
}

// LoadCert returns (nil, nil) when no certificate exists yet.
func (d Dir) LoadCert() (*cert.Cert, error) {
	data, err := os.ReadFile(d.certPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cert.Unmarshal(data)
}
