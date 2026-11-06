// Package statementtest builds statement forms the production signer no
// longer produces, for tests of the rules that still read them.
package statementtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// SignV1 signs p as a version-1 statement — the form the fleet issued
// between 2026-11-02 and 2026-11-06 — so a test can hold a legacy sweep
// ({aud, before}, the cut rule) against the version-2 reading. It fills
// the format fields as statement.Sign does and returns the statement
// through statement.Decode, so it is exactly what a peer would read off
// the wire.
func SignV1(priv ed25519.PrivateKey, p statement.Payload, parent *statement.Statement) (*statement.Statement, error) {
	p.V = 1
	if p.Typ == "" {
		p.Typ = statement.TypeAssert
	}
	p.Iss = did.ForKey(priv.Public().(ed25519.PublicKey))
	p.Acks = nil
	if parent != nil {
		pb, err := parent.Bytes()
		if err != nil {
			return nil, err
		}
		p.Prf = [][]byte{pb}
	} else {
		p.Prf = [][]byte{}
	}
	if p.Nonce == nil {
		p.Nonce = make([]byte, 16)
		if _, err := rand.Read(p.Nonce); err != nil {
			return nil, err
		}
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	msg, err := enc.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encoding payload: %w", err)
	}
	raw, err := enc.Marshal(struct {
		Payload cbor.RawMessage `cbor:"payload"`
		Sig     []byte          `cbor:"sig"`
	}{Payload: msg, Sig: ed25519.Sign(priv, msg)})
	if err != nil {
		return nil, err
	}
	return statement.Decode(raw)
}

// SweepV1 is the legacy device sweep: every statement naming deviceDID in
// circle sub issued up to before is dead. own is the revoker's chain (nil
// for the root).
func SweepV1(priv ed25519.PrivateKey, sub string, own *statement.Statement, deviceDID string, before, now int64) (*statement.Statement, error) {
	return SignV1(priv, statement.Payload{
		Typ: statement.TypeRevoke, Sub: sub, Iat: now, At: now,
		Target: &statement.Target{Aud: deviceDID, Before: before},
	}, own)
}
