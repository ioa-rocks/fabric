package cli

import (
	"flag"
	"reflect"
	"testing"
)

// The usage lines advertise trailing flags (vault put <bucket> <file>
// -tag x); parse must accept flags on either side of positionals, and
// stop recognizing them past the limit so tag's +x/-x modifiers survive.
func TestParseInterleaved(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		limit int
		pos   []string
		tag   string
	}{
		{"flags first", []string{"-tag", "x", "b", "f"}, -1, []string{"b", "f"}, "x"},
		{"flags trailing", []string{"b", "f", "-tag", "x"}, -1, []string{"b", "f"}, "x"},
		{"flags between", []string{"b", "-tag", "x", "f"}, -1, []string{"b", "f"}, "x"},
		{"no flags", []string{"b", "f"}, -1, []string{"b", "f"}, ""},
		{"limit keeps modifiers", []string{"b", "ref", "+x", "-y"}, 2, []string{"b", "ref", "+x", "-y"}, ""},
		{"limit with leading flag", []string{"-tag", "x", "b", "ref", "-y"}, 2, []string{"b", "ref", "-y"}, "x"},
		{"double dash", []string{"b", "--", "-f"}, -1, []string{"b", "-f"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
			tag := fs.String("tag", "", "")
			pos := parse(fs, c.args, c.limit)
			if !reflect.DeepEqual(pos, c.pos) {
				t.Errorf("positionals = %v, want %v", pos, c.pos)
			}
			if *tag != c.tag {
				t.Errorf("-tag = %q, want %q", *tag, c.tag)
			}
		})
	}
}
