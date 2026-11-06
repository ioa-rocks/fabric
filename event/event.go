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
//
// Logs written before 2026-11-05 may still carry `root-moved` and
// `root-retired` records from the one-time mesh-root → circle-main
// migration; Verify refuses them as unknown and they drop out of the log
// like any other stale entry.
const (
	KindAdded   = "member-added"
	KindRevoked = "member-revoked"
)

// Payload is the signed portion of a membership event.
type Payload struct {
	Ns     string `cbor:"ns"`               // signing root, did:key (a circle DID)
	Kind   string `cbor:"kind"`             // one of the Kind constants
	Cert   []byte `cbor:"cert,omitempty"`   // KindAdded: the signed membership cert
	Device []byte `cbor:"device,omitempty"` // KindRevoked: the revoked device pubkey
	At     int64  `cbor:"at"`               // unix seconds
}

// Event is a payload plus the root key's signature over the
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
// circle.
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

// Verify checks the event against roots: its signer must be the root of
// the circle it names, and for MemberAdded events the embedded certificate
// is verified too, so a verified added-event's cert can be trusted as a
// membership proof. An added event whose cert has already expired fails
// verification — it is stale, not dangerous, and callers simply drop it.
func Verify(e *Event, roots statement.Roots, now time.Time) error {
	keys := roots.RootKeys(e.Payload.Ns)
	if len(keys) == 0 {
		return fmt.Errorf("event is signed by %s, a root this node does not honour", e.Payload.Ns)
	}
	// A circle whose key rotated signs its events with the new key; the
	// legacy log has no place for the handover, so every key of the
	// known history signs (the event's cert carries the proof and is
	// judged with it).
	if h, ok := roots.(statement.RootHistory); ok {
		for _, ho := range h.Handovers(e.Payload.Ns) {
			if k, err := did.KeyFor(ho.Payload.Aud); err == nil {
				keys = append(keys, k)
			}
		}
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
	default:
		return fmt.Errorf("unknown event kind %q", e.Payload.Kind)
	}
	return nil
}

// VerifyKey is Verify against a single root key.
func VerifyKey(e *Event, rootPub ed25519.PublicKey, now time.Time) error {
	return Verify(e, statement.NewDIDRoot(cert.DIDForKey(rootPub)), now)
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
