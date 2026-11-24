package fusefs

import "testing"

func TestNoNewPrivsLine(t *testing.T) {
	cases := map[string]bool{
		"Name:\tfabric\nNoNewPrivs:\t1\nSeccomp:\t0\n": true,
		"Name:\tfabric\nNoNewPrivs:\t0\nSeccomp:\t0\n": false,
		"Name:\tfabric\nSeccomp:\t0\n":                 false, // kernel without the field
		"Name:\tNoNewPrivs:\t1\nNoNewPrivs:\t0\n":      false, // only a line that starts with the field counts
		"":               false,
		"NoNewPrivs:\t1": true,
		"Name:\tfabric\nNoNewPrivs:    1   \nSeccomp:0": true,
	}
	for status, want := range cases {
		if got := noNewPrivs([]byte(status)); got != want {
			t.Errorf("%q: %v, want %v", status, got, want)
		}
	}
}
