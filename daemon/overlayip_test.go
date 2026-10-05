package daemon

import (
	"path/filepath"
	"testing"

	"ioa.rocks/fabric/state"
)

// Renumbering (fabric renew -ip) must only hand out addresses that are
// inside the subnet, usable, and not held by anyone else on the roster —
// lapsed members included — while letting a member keep its own.
func TestCheckOverlayIP(t *testing.T) {
	dir, err := state.Open(filepath.Join(t.TempDir(), "fabric"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveConfig(state.Config{Name: "desk", Subnet: "100.64.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	members := []MemberInfo{
		{Name: "desk", Fingerprint: "aaaa", IP: "100.64.0.1/24", Self: true},
		{Name: "nas", Fingerprint: "bbbb", IP: "100.64.0.3/24"},
		{Name: "carbon", Fingerprint: "cccc", IP: "100.64.0.4/24", Expired: true},
	}
	cases := []struct {
		want, fp, got string
		fails         bool
	}{
		{"100.64.0.2", "bbbb", "100.64.0.2/24", false},    // free
		{"100.64.0.2/24", "bbbb", "100.64.0.2/24", false}, // prefix form accepted
		{"100.64.0.3", "bbbb", "100.64.0.3/24", false},    // its own address
		{"100.64.0.1", "bbbb", "", true},                  // the master's
		{"100.64.0.4", "bbbb", "", true},                  // held by a lapsed member
		{"100.64.1.9", "bbbb", "", true},                  // outside the subnet
		{"100.64.0.0", "bbbb", "", true},                  // network address
		{"100.64.0.255", "bbbb", "", true},                // broadcast
		{"nope", "bbbb", "", true},
	}
	for _, c := range cases {
		got, err := CheckOverlayIP(dir, members, c.want, c.fp)
		if (err != nil) != c.fails {
			t.Errorf("%s: err=%v, want failure=%v", c.want, err, c.fails)
			continue
		}
		if got != c.got {
			t.Errorf("%s: got %q, want %q", c.want, got, c.got)
		}
	}
}
