package main

import "testing"

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote("/home/o'neil/fabric"), `'/home/o'\''neil/fabric'`; got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
}
