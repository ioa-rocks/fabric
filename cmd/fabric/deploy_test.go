package main

import "testing"

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote("/home/o'neil/fabric"), `'/home/o'\''neil/fabric'`; got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
}

func TestExecutableFromSystemd(t *testing.T) {
	in := `{ path=/home/user/fabric ; argv[]=/home/user/fabric up -state /home/user/.config/fabric ; ignore_errors=no }`
	got, err := executableFromSystemd(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/home/user/fabric"; got != want {
		t.Fatalf("executable = %q, want %q", got, want)
	}
}
