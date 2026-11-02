// Package event implements signed membership events (security-model spec §5):
// admissions and revocations travel as root-key-signed records on one gossip
// channel, exchanged peer-to-peer between members. Gossip is the real-time
// revocation path; cert expiry remains the backstop for peers the gossip
// never reached.
package event

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"ioa.rocks/fabric/cert"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"

	"github.com/fxamacker/cbor/v2"
)

// Kinds of membership events.
const (
	KindAdded   = "member-added"
	KindRevoked = "member-revoked"
	// KindRootMoved, signed by the circle's current root, says the circle
	// continues under the root named by To (the mesh-root merge: the home
	// circle's key takes over). Nodes honour To from then on and keep the
	// signer honoured until a KindRootRetired, signed by the new root,
	// names it. Together they make the move a gossip, not a flag day.
	KindRootMoved   = "root-moved"
	KindRootRetired = "root-retired"
)

// Payload is the signed portion of a membership event.
type Payload struct {
	Ns     string `cbor:"ns"`               // signing root, did:key (a circle DID)
	Kind   string `cbor:"kind"`             // one of the Kind constants
	Cert   []byte `cbor:"cert,omitempty"`   // KindAdded: the signed membership cert
	Device []byte `cbor:"device,omitempty"` // KindRevoked: the revoked device pubkey
	To     string `cbor:"to,omitempty"`     // KindRootMoved: the root that takes over
	Root   string `cbor:"root,omitempty"`   // KindRootRetired: the root no longer honoured
	At     int64  `cbor:"at"`               // unix seconds
}

// Event is a payload plus the namespace root key's signature over the
// payload's deterministic CBOR encoding.
type Event struct {
	Payload Payload `cbor:"payload"`
	Sig     []byte  `cbor:"sig"`
}

// Deterministic encoding, same requirement as package cert: sign and verify
// must agree on the exact bytes.
var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("event: building CBOR enc mode: %v", err))
	}
}

// NewAdded signs a MemberAdded event announcing a freshly issued certificate.
func NewAdded(rootPriv ed25519.PrivateKey, c *cert.Cert, at time.Time) (*Event, error) {
	certBytes, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return sign(rootPriv, Payload{Kind: KindAdded, Cert: certBytes, At: at.Unix()})
}

// NewRevoked signs a MemberRevoked event cutting a device key out of the
// namespace.
func NewRevoked(rootPriv ed25519.PrivateKey, devicePub ed25519.PublicKey, at time.Time) (*Event, error) {
	if len(devicePub) != ed25519.PublicKeySize {
		return nil, errors.New("device key is not an ed25519 public key")
	}
	return sign(rootPriv, Payload{Kind: KindRevoked, Device: devicePub, At: at.Unix()})
}

// NewRootMoved is signed by the current root: the circle continues under
// the root named by to.
func NewRootMoved(rootPriv ed25519.PrivateKey, to string, at time.Time) (*Event, error) {
	if !did.IsKey(to) {
		return nil, errors.New("root-moved target is not a did:key")
	}
	if to == did.ForKey(rootPriv.Public().(ed25519.PublicKey)) {
		return nil, errors.New("root-moved target is the signing root itself")
	}
	return sign(rootPriv, Payload{Kind: KindRootMoved, To: to, At: at.Unix()})
}

// NewRootRetired is signed by the (new) root: the root named is no longer
// honoured; certificates in its circle stop verifying everywhere.
func NewRootRetired(rootPriv ed25519.PrivateKey, retired string, at time.Time) (*Event, error) {
	if !did.IsKey(retired) {
		return nil, errors.New("root-retired target is not a did:key")
	}
	if retired == did.ForKey(rootPriv.Public().(ed25519.PublicKey)) {
		return nil, errors.New("a root cannot retire itself")
	}
	return sign(rootPriv, Payload{Kind: KindRootRetired, Root: retired, At: at.Unix()})
}

// IsRootEvent reports whether the event is about roots rather than a device.
func (e *Event) IsRootEvent() bool {
	return e.Payload.Kind == KindRootMoved || e.Payload.Kind == KindRootRetired
}

func sign(rootPriv ed25519.PrivateKey, p Payload) (*Event, error) {
	p.Ns = cert.DIDForKey(rootPriv.Public().(ed25519.PublicKey))
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding event payload: %w", err)
	}
	return &Event{Payload: p, Sig: ed25519.Sign(rootPriv, msg)}, nil
}

// Verify checks the event against the honoured roots: its signer must be a
// root honoured for the circle it names, and for MemberAdded events the
// embedded certificate is verified too, so a verified added-event's cert
// can be trusted as a membership proof. An added event whose cert has
// already expired fails verification — it is stale, not dangerous, and
// callers simply drop it.
func Verify(e *Event, roots statement.Roots, now time.Time) error {
	keys := roots.RootKeys(e.Payload.Ns)
	if len(keys) == 0 {
		return fmt.Errorf("event is signed by %s, a root this node does not honour", e.Payload.Ns)
	}
	msg, err := encMode.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("encoding event payload: %w", err)
	}
	signed := false
	for _, k := range keys {
		if ed25519.Verify(k, msg, e.Sig) {
			signed = true
			break
		}
	}
	if !signed {
		return errors.New("event signature verification failed")
	}
	switch e.Payload.Kind {
	case KindAdded:
		c, err := e.AddedCert()
		if err != nil {
			return err
		}
		if err := cert.VerifyRoots(c, roots, now); err != nil {
			return fmt.Errorf("added-event cert: %w", err)
		}
	case KindRevoked:
		if len(e.Payload.Device) != ed25519.PublicKeySize {
			return errors.New("revoked-event device key is not an ed25519 public key")
		}
	case KindRootMoved:
		if !did.IsKey(e.Payload.To) || e.Payload.To == e.Payload.Ns {
			return errors.New("root-moved target is not another did:key")
		}
	case KindRootRetired:
		if !did.IsKey(e.Payload.Root) || e.Payload.Root == e.Payload.Ns {
			return errors.New("root-retired target is not another did:key")
		}
	default:
		return fmt.Errorf("unknown event kind %q", e.Payload.Kind)
	}
	return nil
}

// VerifyKey is Verify against a single root key.
func VerifyKey(e *Event, namespacePub ed25519.PublicKey, now time.Time) error {
	return Verify(e, statement.NewDIDRoots(cert.DIDForKey(namespacePub)), now)
}

// AddedCert decodes the certificate carried by a MemberAdded event.
func (e *Event) AddedCert() (*cert.Cert, error) {
	if e.Payload.Kind != KindAdded {
		return nil, fmt.Errorf("not a %s event", KindAdded)
	}
	return cert.Unmarshal(e.Payload.Cert)
}

// DeviceKey returns the device public key the event is about.
func (e *Event) DeviceKey() (ed25519.PublicKey, error) {
	switch e.Payload.Kind {
	case KindAdded:
		c, err := e.AddedCert()
		if err != nil {
			return nil, err
		}
		return c.DeviceKey()
	case KindRevoked:
		return ed25519.PublicKey(e.Payload.Device), nil
	default:
		return nil, fmt.Errorf("unknown event kind %q", e.Payload.Kind)
	}
}

// ID is the event's dedup key: the hash of its deterministic payload
// encoding.
func (e *Event) ID() string {
	msg, err := encMode.Marshal(e.Payload)
	if err != nil {
		// The payload was decoded from CBOR or built by this package;
		// re-encoding it cannot fail.
		panic(fmt.Sprintf("event: encoding payload: %v", err))
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:])
}

// Time returns when the event was signed.
func (e *Event) Time() time.Time { return time.Unix(e.Payload.At, 0) }

// Marshal encodes the event for the wire or disk.
func (e *Event) Marshal() ([]byte, error) { return encMode.Marshal(e) }

// Unmarshal decodes an event. The result is untrusted until Verify passes.
func Unmarshal(data []byte) (*Event, error) {
	var e Event
	if err := cbor.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("decoding event: %w", err)
	}
	return &e, nil
}
