// Package cert implements the Fabric membership certificate: a minimal
// ed25519-signed DAG-CBOR struct whose field names deliberately mirror the
// UCAN 1.0 delegation payload (iss/aud/sub/cmd/nbf/exp/nonce/prf), so a
// later migration to real UCANs is a serialization change, not a data-model
// change. See the security-model spec §2 and the UCAN-in-Go survey for why
// this is hand-rolled rather than go-ucan.
package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Command paths — the role field, expressed as a UCAN command path.
const (
	CmdMember = "/fabric/member"
	CmdAdmin  = "/fabric/admin"
)

const nonceSize = 16

// Meta carries non-security-relevant labels.
type Meta struct {
	Name string `cbor:"name"` // human label, e.g. "nas", "work-laptop"
}

// Payload is the signed portion of a membership certificate.
type Payload struct {
	Iss   string   `cbor:"iss"` // issuer: namespace root key, did:key
	Aud   string   `cbor:"aud"` // audience: the member device key, did:key
	Sub   string   `cbor:"sub"` // subject: resource owner; == Iss until delegation lands
	Cmd   string   `cbor:"cmd"` // role: CmdMember or CmdAdmin
	Meta  Meta     `cbor:"meta"`
	Nbf   int64    `cbor:"nbf"` // not before, unix seconds
	Exp   int64    `cbor:"exp"` // expiry, unix seconds
	Nonce []byte   `cbor:"nonce"`
	Prf   [][]byte `cbor:"prf"` // proof chain (CIDs); must be empty until
	//    delegation (ADR 0010), but verifiers parse it so multi-admin is a
	//    policy change, not a format break.
}

// Cert is a payload plus the namespace root key's signature over the
// payload's deterministic CBOR encoding.
type Cert struct {
	Payload Payload `cbor:"payload"`
	Sig     []byte  `cbor:"sig"`
}

// Deterministic encoding (RFC 8949 core deterministic requirements) so that
// sign and verify agree on the exact bytes.
var encMode cbor.EncMode

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("cert: building CBOR enc mode: %v", err))
	}
}

// Issue signs a membership certificate for a device key. rootPriv is the
// namespace root private key; it never leaves the master (spec §1).
func Issue(rootPriv ed25519.PrivateKey, devicePub ed25519.PublicKey, cmd, name string, nbf time.Time, validity time.Duration) (*Cert, error) {
	if cmd != CmdMember && cmd != CmdAdmin {
		return nil, fmt.Errorf("unknown command path %q", cmd)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	rootDID := DIDForKey(rootPriv.Public().(ed25519.PublicKey))
	p := Payload{
		Iss:   rootDID,
		Aud:   DIDForKey(devicePub),
		Sub:   rootDID,
		Cmd:   cmd,
		Meta:  Meta{Name: name},
		Nbf:   nbf.Unix(),
		Exp:   nbf.Add(validity).Unix(),
		Nonce: nonce,
		Prf:   [][]byte{},
	}
	msg, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	return &Cert{Payload: p, Sig: ed25519.Sign(rootPriv, msg)}, nil
}

// Verify checks a certificate against the expected namespace root public key
// at the given time. It returns nil only if the cert is a currently valid
// membership proof for this namespace.
func Verify(c *Cert, namespacePub ed25519.PublicKey, now time.Time) error {
	issKey, err := KeyForDID(c.Payload.Iss)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if !bytes.Equal(issKey, namespacePub) {
		return errors.New("issuer is not this namespace's root key")
	}
	// Until delegation chains land, the issuer must own the namespace and
	// the proof chain must be empty (parsed, but rejected — spec §2).
	if c.Payload.Sub != c.Payload.Iss {
		return errors.New("delegated certificates not yet supported (sub != iss)")
	}
	if len(c.Payload.Prf) != 0 {
		return errors.New("delegated certificates not yet supported (non-empty prf)")
	}
	if c.Payload.Cmd != CmdMember && c.Payload.Cmd != CmdAdmin {
		return fmt.Errorf("unknown command path %q", c.Payload.Cmd)
	}
	if now.Unix() < c.Payload.Nbf {
		return errors.New("certificate not yet valid")
	}
	if now.Unix() > c.Payload.Exp {
		return errors.New("certificate expired")
	}
	msg, err := encMode.Marshal(c.Payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}
	if !ed25519.Verify(namespacePub, msg, c.Sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// DeviceKey returns the member device's public key (the audience).
func (c *Cert) DeviceKey() (ed25519.PublicKey, error) {
	return KeyForDID(c.Payload.Aud)
}

// Expiry returns the certificate's expiry time.
func (c *Cert) Expiry() time.Time {
	return time.Unix(c.Payload.Exp, 0)
}

// Marshal encodes the certificate for the wire.
func (c *Cert) Marshal() ([]byte, error) {
	return encMode.Marshal(c)
}

// Unmarshal decodes a certificate from the wire. The result is untrusted
// until Verify passes.
func Unmarshal(data []byte) (*Cert, error) {
	var c Cert
	if err := cbor.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}
	return &c, nil
}
