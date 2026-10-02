package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
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
	if !metaEqual(renewed.Payload.Meta, old.Payload.Meta) {
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
		Name string `cbor:"name"`
		IP   string `cbor:"ip,omitempty"`
		Ring string `cbor:"ring,omitempty"` // unknown here
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
		Meta:  futureMeta{Name: "guest-pc", Ring: "guest"},
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
	if !metaEqual(legacy.Payload.Meta, c.Payload.Meta) || legacy.Payload.Aud != c.Payload.Aud || legacy.Payload.Exp != c.Payload.Exp ||
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

func metaEqual(a, b Meta) bool {
	return a.Name == b.Name && a.IP == b.IP && slices.Equal(a.Scope, b.Scope)
}

func TestScopeSemantics(t *testing.T) {
	// Absent scope: everything. Present: control plane + listed families.
	for _, f := range []string{"", ScopeTun, ScopeVault, ScopeAstral, "nexus"} {
		if !ScopeAllows(nil, f) {
			t.Fatalf("unscoped cert must allow %q", f)
		}
	}
	vaultOnly := []string{ScopeVault}
	if !ScopeAllows(vaultOnly, "") || !ScopeAllows(vaultOnly, ScopeVault) {
		t.Fatal("scoped cert must allow the control plane and its own family")
	}
	if ScopeAllows(vaultOnly, ScopeTun) || ScopeAllows(vaultOnly, ScopeAstral) || ScopeAllows(vaultOnly, "nexus") {
		t.Fatal("scoped cert allowed a family it does not list")
	}
	meshOnly := []string{ScopeMesh}
	if !ScopeAllows(meshOnly, "") || ScopeAllows(meshOnly, ScopeVault) {
		t.Fatal("mesh-only scope must allow only the control plane")
	}

	cases := map[string]string{
		"/fabric/tun/1": ScopeTun, "/vault/sync/2": ScopeVault, "/vault/blob/1": ScopeVault,
		"/astral/subject/1": ScopeAstral, "/fabric/auth/1": "", "/fabric/sync/1": "",
		"/fabric/links/1": "", "/ipfs/ping/1.0.0": "",
	}
	for proto, want := range cases {
		if got := ScopeFamily(proto); got != want {
			t.Errorf("ScopeFamily(%q) = %q, want %q", proto, got, want)
		}
	}
}

func TestScopeNormalize(t *testing.T) {
	if s, err := ParseScope(""); err != nil || s != nil {
		t.Fatalf("empty scope must be unrestricted, got %v %v", s, err)
	}
	if s, err := ParseScope("full"); err != nil || s != nil {
		t.Fatalf("'full' must be unrestricted, got %v %v", s, err)
	}
	if s, err := ParseScope("vault, astral,vault"); err != nil || !slices.Equal(s, []string{ScopeVault, ScopeAstral}) {
		t.Fatalf("dedupe/trim failed: %v %v", s, err)
	}
	if s, err := ParseScope("mesh"); err != nil || !slices.Equal(s, []string{ScopeMesh}) {
		t.Fatalf("mesh-only must stay explicit on the wire, got %v %v", s, err)
	}
	if s, err := ParseScope("mesh,tun"); err != nil || !slices.Equal(s, []string{ScopeTun}) {
		t.Fatalf("mesh is implied when a family is present, got %v %v", s, err)
	}
	if _, err := ParseScope("tun,nexus"); err == nil {
		t.Fatal("unknown family accepted")
	}
	if !slices.Equal(ScopeWithout(ScopeTun), []string{ScopeVault, ScopeAstral}) {
		t.Fatalf("ScopeWithout(tun) = %v", ScopeWithout(ScopeTun))
	}
}

// A mesh-only scope must survive the wire: omitempty would silently turn an
// empty list into "unrestricted", which is why NormalizeScope keeps "mesh".
func TestScopeRoundTripAndRenewMeta(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()
	c, err := Issue(nsPriv, devPub, CmdMember, Meta{Name: "guest", Scope: []string{ScopeMesh}}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := c.Marshal()
	back, err := Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, nsPub, now); err != nil {
		t.Fatal(err)
	}
	if back.Allows(ScopeVault) || !back.Allows("") {
		t.Fatalf("mesh-only scope lost on the wire: %v", back.Payload.Meta.Scope)
	}

	// Promotion is a renewal: same identity, new scope and address.
	meta := back.Payload.Meta
	meta.Scope = []string{ScopeVault}
	promoted, err := RenewMeta(nsPriv, back, meta, now.Add(time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(promoted, nsPub, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if promoted.Payload.Aud != back.Payload.Aud || promoted.Payload.Cmd != back.Payload.Cmd {
		t.Fatal("renewal changed identity or role")
	}
	if !promoted.Allows(ScopeVault) || promoted.Allows(ScopeTun) {
		t.Fatalf("promoted scope wrong: %v", promoted.Payload.Meta.Scope)
	}
}
