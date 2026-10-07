package daemon_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"ioa.rocks/fabric/vault/daemon"
)

func TestObjectPageAPI(t *testing.T) {
	dir := t.TempDir()
	initCircle(t, dir, "alex")
	startDaemon(t, dir)
	cl := daemon.NewClient(dir)
	genesis, policy := signBucket(t, dir, "pw", "files")
	if _, err := cl.CreateBucket(genesis, policy); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 205; i++ {
		if _, err := cl.Put("files", fmt.Sprintf("file-%d", i), strings.NewReader("x"), []string{"test"}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for _, want := range []int{100, 100, 5} {
		page, err := cl.ListPage(context.Background(), "files", cursor, []string{"test"})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Objects) != want {
			t.Fatalf("page length %d, want %d", len(page.Objects), want)
		}
		for _, o := range page.Objects {
			if seen[o.ID] {
				t.Fatal("duplicate object")
			}
			seen[o.ID] = true
		}
		cursor = page.Next
	}
	if len(seen) != 205 || cursor != "" {
		t.Fatalf("incomplete traversal: %d, %q", len(seen), cursor)
	}
	if _, err := cl.ListPage(context.Background(), "files", "bad-cursor", nil); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	// The pre-existing complete listing remains compatible for CLI/API users.
	all, err := cl.List("files", nil)
	if err != nil || len(all) != 205 {
		t.Fatalf("legacy list: %d, %v", len(all), err)
	}
}
