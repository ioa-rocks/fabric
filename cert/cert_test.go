package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestDIDRoundtrip(t *testing.T) {
	pub, _ := genKey(t)
	did := DIDForKey(pub)
	got, err := KeyForDID(did)
	if err != nil {
		t.Fatalf("KeyForDID(%q): %v", did, err)
	}
	if !pub.Equal(got) {
		t.Fatalf("roundtrip mismatch: %x != %x", pub, got)
	}
}

func TestKeyForDIDRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"did:key:zabc!!!",
		"did:web:example.com",
		"did:key:z" + "1111", // too short after decode
	} {
		if _, err := KeyForDID(bad); err == nil {
			t.Errorf("KeyForDID(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestIssueVerifyRoundtrip(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()

	c, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "nas"}, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, nsPub, now.Add(time.Hour)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	dev, err := back.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if !devPub.Equal(dev) {
		t.Fatal("device key mismatch after roundtrip")
	}
	if back.Payload.Meta.Name != "nas" {
		t.Fatalf("name = %q, want nas", back.Payload.Meta.Name)
	}
}

func TestVerifyRejections(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	otherPub, otherPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()

	valid := func(t *testing.T) *Cert {
		t.Helper()
		c, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "x"}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("wrong namespace", func(t *testing.T) {
		if err := Verify(valid(t), otherPub, now); err == nil {
			t.Fatal("verified against wrong namespace key")
		}
	})
	t.Run("expired", func(t *testing.T) {
		if err := Verify(valid(t), nsPub, now.Add(2*time.Hour)); err == nil {
			t.Fatal("verified an expired cert")
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		if err := Verify(valid(t), nsPub, now.Add(-time.Hour)); err == nil {
			t.Fatal("verified a not-yet-valid cert")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		// Tamper on the wire — the bytes the signature covers. (The parsed
		// struct is read-only by contract; edits to it are neither signed
		// over nor emitted.)
		wire, err := valid(t).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var w wireCert
		if err := cbor.Unmarshal(wire, &w); err != nil {
			t.Fatal(err)
		}
		var p Payload
		if err := cbor.Unmarshal(w.Payload, &p); err != nil {
			t.Fatal(err)
		}
		p.Cmd = CmdAdmin // privilege escalation attempt
		w.Payload, err = encMode.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		tampered, err := encMode.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Unmarshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if c.Payload.Cmd != CmdAdmin {
			t.Fatal("test setup: tamper did not land")
		}
		if err := Verify(c, nsPub, now); err == nil {
			t.Fatal("verified a tampered cert")
		}
	})
	t.Run("forged signature", func(t *testing.T) {
		c := valid(t)
		forged, err := Issue(otherPriv, devPub, CmdMember, Meta{Name: "x"}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		c.Sig = forged.Sig
		if err := Verify(c, nsPub, now); err == nil {
			t.Fatal("verified a cert with a foreign signature")
		}
	})
	t.Run("non-empty prf rejected", func(t *testing.T) {
		c := valid(t)
		c.Payload.Prf = [][]byte{{0x01}}
		if err := Verify(c, nsPub, now); err == nil {
			t.Fatal("verified a cert with a proof chain before delegation support")
		}
	})
}

func TestRenewPreservesPayload(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	issued := time.Now().Add(-300 * 24 * time.Hour) // deep into its life
	old, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "nas", IP: "100.64.0.7/24"}, issued, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	renewed, err := Renew(nsPriv, old, now, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(renewed, nsPub, now); err != nil {
		t.Fatalf("renewed cert does not verify: %v", err)
	}

	// Identity, role, and addressing must be untouched — a renewal that
	// renumbers a node breaks TUN routing and MagicDNS (spec §5).
	if renewed.Payload.Aud != old.Payload.Aud || renewed.Payload.Iss != old.Payload.Iss ||
		renewed.Payload.Sub != old.Payload.Sub || renewed.Payload.Cmd != old.Payload.Cmd {
		t.Fatal("renewal changed identity/role fields")
	}
	if renewed.Payload.Meta != old.Payload.Meta {
		t.Fatalf("renewal changed meta: %+v != %+v", renewed.Payload.Meta, old.Payload.Meta)
	}
	if !renewed.Expiry().After(old.Expiry()) {
		t.Fatalf("renewal did not extend expiry: %v <= %v", renewed.Expiry(), old.Expiry())
	}
	if string(renewed.Payload.Nonce) == string(old.Payload.Nonce) {
		t.Fatal("renewal reused the nonce")
	}
}

func TestRenewRejectsForeignRootKey(t *testing.T) {
	_, nsPriv := genKey(t)
	_, otherPriv := genKey(t)
	devPub, _ := genKey(t)
	old, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "nas"}, time.Now(), DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Renew(otherPriv, old, time.Now(), DefaultValidity); err == nil {
		t.Fatal("renewal with a foreign root key unexpectedly succeeded")
	}
}

// A cert whose payload carries fields this binary does not know (a future
// scope attribute, fabric ADR 0005) must still verify, and must leave this
// node byte-for-byte as it arrived — otherwise the fleet could never be
// upgraded ahead of the first scoped cert.
func TestVerifyAndForwardUnknownPayloadFields(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()

	// The same payload as a hypothetical newer binary would encode it.
	type futureMeta struct {
		Name  string `cbor:"name"`
		IP    string `cbor:"ip,omitempty"`
		Scope string `cbor:"scope,omitempty"` // unknown here
	}
	type futurePayload struct {
		Iss   string     `cbor:"iss"`
		Aud   string     `cbor:"aud"`
		Sub   string     `cbor:"sub"`
		Cmd   string     `cbor:"cmd"`
		Meta  futureMeta `cbor:"meta"`
		Nbf   int64      `cbor:"nbf"`
		Exp   int64      `cbor:"exp"`
		Nonce []byte     `cbor:"nonce"`
		Prf   [][]byte   `cbor:"prf"`
		Ext   string     `cbor:"ext,omitempty"` // unknown top-level field
	}
	rootDID := DIDForKey(nsPub)
	fp := futurePayload{
		Iss: rootDID, Aud: DIDForKey(devPub), Sub: rootDID, Cmd: CmdMember,
		Meta:  futureMeta{Name: "guest-pc", Scope: "tun=none"},
		Nbf:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
		Nonce: make([]byte, nonceSize),
		Prf:   [][]byte{},
		Ext:   "something newer",
	}
	payload, err := encMode.Marshal(fp)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encMode.Marshal(wireCert{Payload: payload, Sig: ed25519.Sign(nsPriv, payload)})
	if err != nil {
		t.Fatal(err)
	}

	c, err := Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if c.Payload.Meta.Name != "guest-pc" {
		t.Fatalf("known fields must still parse: %+v", c.Payload.Meta)
	}
	if err := Verify(c, nsPub, now.Add(time.Minute)); err != nil {
		t.Fatalf("Verify with unknown fields: %v", err)
	}
	again, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, wire) {
		t.Fatal("re-marshalling dropped or reordered payload fields")
	}
	// And the forwarded bytes verify on the next hop too.
	hop, err := Unmarshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(hop, nsPub, now.Add(time.Minute)); err != nil {
		t.Fatalf("Verify after forwarding: %v", err)
	}
}

// The wire shape must not have changed: a cert issued and marshalled here
// decodes with the pre-raw-payload layout (payload map + sig).
func TestWireShapeUnchanged(t *testing.T) {
	_, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	c, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "nas", IP: "100.64.0.9/24"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Payload Payload `cbor:"payload"`
		Sig     []byte  `cbor:"sig"`
	}
	if err := cbor.Unmarshal(wire, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Payload.Meta != c.Payload.Meta || legacy.Payload.Aud != c.Payload.Aud || legacy.Payload.Exp != c.Payload.Exp ||
		!bytes.Equal(legacy.Payload.Nonce, c.Payload.Nonce) || !bytes.Equal(legacy.Sig, c.Sig) {
		t.Fatal("legacy layout decode differs")
	}
	relegacy, err := encMode.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(relegacy, wire) {
		t.Fatal("legacy re-encoding is not byte-identical to the new Marshal")
	}
}
