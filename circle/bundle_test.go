package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// A device bundle carries the circle's config (gate hints, prefix) and the
// device's admission, no key: the joining device is a device, not an
// owner; its admission is installed and its role reads off the verbs.
func TestDeviceBundleJoinsWithoutKey(t *testing.T) {
	owner, err := Init(t.TempDir(), "family", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.SetPrefix(DefaultPrefix(owner.Config.DID)); err != nil {
		t.Fatal(err)
	}
	priv, _ := owner.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	verbs, err := VerbsForRole(RoleGate)
	if err != nil {
		t.Fatal(err)
	}
	a, err := AdmitWith(priv, nil, owner.Config.DID, devPub, time.Now(), time.Hour, verbs, &statement.Meta{Name: "gate-hetz"})
	if err != nil {
		t.Fatal(err)
	}
	gates := []string{"/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BE4xHGa2yR8bVDk6M4V4m"}
	b, err := NewDeviceBundle(owner, a, gates)
	if err != nil {
		t.Fatal(err)
	}
	if b.HasKey() {
		t.Fatal("device bundle carries a key")
	}
	file := filepath.Join(t.TempDir(), "gate.bundle")
	if err := WriteBundle(file, b); err != nil {
		t.Fatal(err)
	}
	read, err := ReadBundle(file)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := Join(t.TempDir(), read)
	if err != nil {
		t.Fatal(err)
	}
	if joined.HasKey() {
		t.Fatal("joined device holds the key")
	}
	if _, err := joined.Unlock("pw"); err == nil {
		t.Fatal("a device without the key unlocked it")
	}
	if joined.Config.Prefix != owner.Config.Prefix || len(joined.Config.Gates) != 1 || joined.Config.Gates[0] != gates[0] {
		t.Fatalf("joined config %+v lost prefix or gate hints", joined.Config)
	}
	got, err := joined.LoadAdmission()
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != did.ForKey(devPub) || got.Role() != RoleGate || got.Name != "gate-hetz" {
		t.Fatalf("installed admission: device %s role %s name %q", got.Device, got.Role(), got.Name)
	}
	if got.Verify(devPub, time.Now()) != nil {
		t.Fatal("installed admission does not verify")
	}
	// A key-less circle exports nothing: there is no key to copy.
	if _, err := joined.Export(); err == nil {
		t.Fatal("a device exported an owner bundle without a key")
	}
	// An admission for another circle is refused at join.
	other, _ := Init(t.TempDir(), "other", "pw")
	bad := &Bundle{Config: other.Config, Admission: read.Admission}
	if _, err := Join(t.TempDir(), bad); err == nil {
		t.Fatal("bundle with a foreign admission joined")
	}
}

// The default overlay prefix is one /24 in 100.64.0.0/10, a function of the
// circle DID alone; an address signed with tun must lie in it.
func TestDefaultPrefixAndTunAddress(t *testing.T) {
	c, _ := Init(t.TempDir(), "p", "pw")
	p1 := DefaultPrefix(c.Config.DID)
	if p1 != DefaultPrefix(c.Config.DID) {
		t.Fatal("DefaultPrefix is not deterministic")
	}
	pfx, err := netip.ParsePrefix(p1)
	if err != nil {
		t.Fatal(err)
	}
	if pfx.Bits() != 24 || !netip.MustParsePrefix("100.64.0.0/10").Contains(pfx.Addr()) {
		t.Fatalf("default prefix %s is not a /24 in 100.64.0.0/10", p1)
	}
	priv, _ := c.Unlock("pw")
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	verbs := append(DeviceVerbs, statement.VerbTun)
	a, err := AdmitWith(priv, nil, c.Config.DID, devPub, time.Now(), time.Hour, verbs, &statement.Meta{Name: "nas", IP: pfx.Addr().Next().String() + "/24"})
	if err != nil {
		t.Fatal(err)
	}
	if a.IP == "" || a.Role() != RoleDevice {
		t.Fatalf("tun admission: ip %q role %s", a.IP, a.Role())
	}
	if _, err := AdmitWith(priv, nil, c.Config.DID, devPub, time.Now(), time.Hour, DeviceVerbs, &statement.Meta{IP: "100.64.0.9/24"}); err == nil {
		t.Fatal("an address without tun was signed")
	}
}
