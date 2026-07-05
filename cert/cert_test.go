package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
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
		c := valid(t)
		c.Payload.Cmd = CmdAdmin // privilege escalation attempt
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
