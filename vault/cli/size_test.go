package cli

import "testing"

func TestParseSize(t *testing.T) {
	for text, want := range map[string]int64{
		"none": 0, "0": 0, "512": 512, "4K": 4 << 10, "20G": 20 << 30, "20GiB": 20 << 30,
		"1.5g": 3 << 29, "2T": 2 << 40, "300MB": 300 << 20,
	} {
		if got, err := parseSize(text); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "-1G", "lots", "G", "1e30T"} {
		if got, err := parseSize(text); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", text, got)
		}
	}
}
