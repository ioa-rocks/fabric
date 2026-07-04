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

	"aethera.dev/fabric/cert"

	"github.com/fxamacker/cbor/v2"
)

// Kinds of membership events.
const (
	KindAdded   = "member-added"
	KindRevoked = "member-revoked"
)

// Payload is the signed portion of a membership event.
type Payload struct {
	Ns     string `cbor:"ns"`               // namespace root key, did:key
	Kind   string `cbor:"kind"`             // KindAdded or KindRevoked
	Cert   []byte `cbor:"cert,omitempty"`   // KindAdded: the signed membership cert
	Device []byte `cbor:"device,omitempty"` // KindRevoked: the revoked device pubkey
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

func sign(rootPriv ed25519.PrivateKey, p Payload) (*Event, error) {
	p.Ns = cert.DIDForKey(rootPriv.Public().(ed25519.PublicKey))
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding event payload: %w", err)
	}
	return &Event{Payload: p, Sig: ed25519.Sign(rootPriv, msg)}, nil
}

// Verify checks the event against the expected namespace root key. For
// MemberAdded events the embedded certificate is verified too, so a verified
// added-event's cert can be trusted as a membership proof. An added event
// whose cert has already expired fails verification — it is stale, not
// dangerous, and callers simply drop it.
func Verify(e *Event, namespacePub ed25519.PublicKey, now time.Time) error {
	if e.Payload.Ns != cert.DIDForKey(namespacePub) {
		return errors.New("event is not from this namespace's root key")
	}
	msg, err := encMode.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("encoding event payload: %w", err)
	}
	if !ed25519.Verify(namespacePub, msg, e.Sig) {
		return errors.New("event signature verification failed")
	}
	switch e.Payload.Kind {
	case KindAdded:
		c, err := e.AddedCert()
		if err != nil {
			return err
		}
		if err := cert.Verify(c, namespacePub, now); err != nil {
			return fmt.Errorf("added-event cert: %w", err)
		}
	case KindRevoked:
		if len(e.Payload.Device) != ed25519.PublicKeySize {
			return errors.New("revoked-event device key is not an ed25519 public key")
		}
	default:
		return fmt.Errorf("unknown event kind %q", e.Payload.Kind)
	}
	return nil
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
