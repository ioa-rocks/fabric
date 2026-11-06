package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/statement"
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

	t.Run("wrong circle", func(t *testing.T) {
		if err := Verify(valid(t), otherPub, now); err == nil {
			t.Fatal("verified against wrong circle key")
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
		var w struct {
			Payload cbor.RawMessage `cbor:"payload"`
			Sig     []byte          `cbor:"sig"`
		}
		if err := cbor.Unmarshal(wire, &w); err != nil {
			t.Fatal(err)
		}
		// Flip the member verb's last byte: a different payload under the
		// same signature.
		i := bytes.LastIndex(w.Payload, []byte(statement.VerbMember))
		if i < 0 {
			t.Fatal("fixture: member verb not found in the payload")
		}
		w.Payload[i+len(statement.VerbMember)-1] ^= 1
		tampered, err := cbor.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		if c, err := Unmarshal(tampered); err == nil && Verify(c, nsPub, now) == nil {
			t.Fatal("tampered cert verified")
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
	t.Run("delegated cert verifies through its chain", func(t *testing.T) {
		deskPub, deskPriv := genKey(t)
		// A plain admin cert is not delegable (hot device key); a desk admission
		// is issued delegable explicitly.
		plain, _ := Issue(nsPriv, deskPub, CmdAdmin, Meta{Name: "desk"}, now, time.Hour)
		if plain.Stmt.Payload.Del != 0 {
			t.Fatalf("admin cert del %d, want 0", plain.Stmt.Payload.Del)
		}
		if viaPlain, _ := IssueAs(deskPriv, plain.Stmt, DIDForKey(nsPub), devPub, CmdMember, Meta{Name: "nas"}, now, time.Hour); viaPlain != nil {
			if err := Verify(viaPlain, nsPub, now.Add(time.Minute)); err == nil {
				t.Fatal("a cert issued under a non-delegable admin cert verified")
			}
		}
		desk, err := IssueAsDel(nsPriv, nil, DIDForKey(nsPub), deskPub, CmdAdmin, Meta{Name: "desk"}, now, time.Hour, 3)
		if err != nil {
			t.Fatal(err)
		}
		c, err := IssueAs(deskPriv, desk.Stmt, DIDForKey(nsPub), devPub, CmdMember, Meta{Name: "nas"}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := c.Marshal()
		back, err := Unmarshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(back, nsPub, now.Add(time.Minute)); err != nil {
			t.Fatalf("desk-issued cert: %v", err)
		}
		if back.Payload.Iss != DIDForKey(deskPub) || back.Payload.Sub != DIDForKey(nsPub) || back.Payload.Cmd != CmdMember {
			t.Fatalf("view: %+v", back.Payload)
		}
		// A device (no admin) cannot issue certs.
		member, _ := Issue(nsPriv, deskPub, CmdMember, Meta{Name: "laptop"}, now, time.Hour)
		rogue, err := IssueAs(deskPriv, member.Stmt, DIDForKey(nsPub), devPub, CmdMember, Meta{Name: "nas"}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(rogue, nsPub, now.Add(time.Minute)); err == nil {
			t.Fatal("a member device issued a verifying cert")
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
// attribute) must still verify, and must leave this node byte-for-byte as
// it arrived — otherwise the fleet could never be upgraded ahead of the
// first cert carrying the attribute. The statement keeps the signed bytes;
// this checks the cert view over it.
func TestVerifyAndForwardUnknownPayloadFields(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	// The same payload as a hypothetical newer binary would encode it:
	// a statement with an unknown meta attribute and an unknown top-level
	// field.
	rootDID := DIDForKey(nsPub)
	payload, err := enc.Marshal(map[string]any{
		"v": statement.Version, "typ": statement.TypeAssert,
		"iss": rootDID, "aud": DIDForKey(devPub), "sub": rootDID,
		"res":   []map[string]any{{"kind": statement.Any, "name": statement.Any, "sub": statement.Any}},
		"verbs": []string{statement.VerbMember},
		"nbf":   now.Unix(), "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"meta": map[string]any{"name": "guest-pc", "ring": "guest"},
		"prf":  [][]byte{},
		"ext":  "something newer",
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := enc.Marshal(map[string]any{"payload": cbor.RawMessage(payload), "sig": ed25519.Sign(nsPriv, payload)})
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

// A fresh cert is a statement on the wire: it decodes with package
// statement, labels as a admission, and the Payload view derives role
// and scope from its verbs. Pre-statement bytes no longer decode.
func TestStatementCertWire(t *testing.T) {
	nsPub, nsPriv := genKey(t)
	devPub, _ := genKey(t)
	now := time.Now()
	c, err := Issue(nsPriv, devPub, CmdAdmin, Meta{Name: "desk", IP: "100.64.0.1/24", Scope: []string{ScopeTun, ScopeVault}}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := c.Marshal()
	s, err := statement.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if s.Label() != "admin admission" || s.Payload.Del != 0 {
		t.Fatalf("label %q del %d", s.Label(), s.Payload.Del)
	}
	back, _ := Unmarshal(wire)
	if back.Stmt == nil || back.Payload.Cmd != CmdAdmin || !slices.Equal(back.Payload.Meta.Scope, []string{ScopeTun, ScopeVault}) ||
		back.Payload.Meta.IP != "100.64.0.1/24" || !back.Allows(ScopeTun) || back.Allows(ScopeAstral) || !back.Allows("") {
		t.Fatalf("view: %+v", back.Payload)
	}
	if err := Verify(back, nsPub, now); err != nil {
		t.Fatal(err)
	}

	// A {payload, sig} frame whose payload is not a statement is refused.
	rootDID := DIDForKey(nsPub)
	oldPayload, _ := cbor.Marshal(map[string]any{"iss": rootDID, "aud": DIDForKey(devPub), "sub": rootDID, "cmd": CmdMember, "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	oldWire, _ := cbor.Marshal(map[string]any{"payload": oldPayload, "sig": ed25519.Sign(nsPriv, oldPayload)})
	if _, err := Unmarshal(oldWire); err == nil || !strings.Contains(err.Error(), "fabric renew") {
		t.Fatalf("pre-statement cert decoded, or without the remedy: %v", err)
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
