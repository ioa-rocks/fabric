package scripts

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sandboxLines runs the installer's sandbox_lines on a `fabric up -paths`
// report, as the installer does, without systemd or root.
func sandboxLines(t *testing.T, report string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	script, absErr := filepath.Abs("install-systemd.sh")
	if absErr != nil {
		t.Fatal(absErr)
	}
	cmd := exec.Command("bash", append([]string{"-c", `source "$1"; shift; sandbox_lines "$@"`, "installer-test", script}, args...)...)
	cmd.Stdin = strings.NewReader(report)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

const plainReport = "state\t/home/u/.config/fabric\n" +
	"socket\t/home/u/.config/fabric/control.sock\n" +
	"state\t/home/u/.local/share/vault\n" +
	"socket\t/home/u/.local/share/vault/control.sock\n" +
	"state\t/home/u/.local/share/astral\n" +
	"socket\t/home/u/.local/share/astral/control.sock\n"

func TestSandboxBindsOnlyWhatTheDaemonNames(t *testing.T) {
	report := plainReport + "folder\t/home/u/My Documents/50% done\nroot\t/mnt/array/vault\n"
	out, stderr, err := sandboxLines(t, report, "/home/u", "/home/u/.local/bin/fabric", "/srv/extra")
	if err != nil {
		t.Fatalf("sandbox_lines: %v\n%s", err, stderr)
	}
	for _, want := range []string{
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=tmpfs",
		`BindReadOnlyPaths="/home/u/.local/bin/fabric"`,
		`BindPaths="/home/u/.config/fabric"`,
		`BindPaths="/home/u/.local/share/vault"`,
		`BindPaths="/home/u/.local/share/astral"`,
		// Declared and requested directories may be absent: "-" skips them.
		// A percent sign is doubled so systemd does not read a specifier.
		`BindPaths="-/home/u/My Documents/50%% done"`,
		`BindPaths="-/mnt/array/vault"`,
		`BindPaths="-/srv/extra"`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s in:\n%s", want, out)
		}
	}
	if got := strings.Count(out, "BindPaths="); got != 6 {
		t.Errorf("%d writable binds, want 6:\n%s", got, out)
	}
	// A home under /home is hidden by ProtectHome alone.
	if strings.Contains(out, "TemporaryFileSystem=") {
		t.Errorf("unexpected TemporaryFileSystem for a home under /home:\n%s", out)
	}
}

func TestSandboxHidesAHomeOutsideHome(t *testing.T) {
	report := "state\t/var/lib/fabric/state\nsocket\t/var/lib/fabric/state/control.sock\n"
	out, stderr, err := sandboxLines(t, report, "/var/lib/fabric", "/var/lib/fabric/.local/bin/fabric")
	if err != nil {
		t.Fatalf("sandbox_lines: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, `TemporaryFileSystem="/var/lib/fabric":ro`+"\n") {
		t.Errorf("home outside /home is not hidden:\n%s", out)
	}
}

// TestSandboxRefusals: each of these would leave a sandboxed daemon unable
// to do what it has declared, or cut off from its clients or its data. The
// installer must stop before it writes anything, so nothing reaches stdout.
func TestSandboxRefusals(t *testing.T) {
	cases := []struct {
		name, report, wantErr string
	}{
		{"declared mount", plainReport + "mount\t/home/u/Cloud/vault\n", "/home/u/Cloud/vault"},
		{"store not yet moved", plainReport + "legacy\t/home/u/.config/vault\n", "/home/u/.config/vault"},
		{"socket in the temp directory", "state\t/long/state\nsocket\t/tmp/fabric-ab12.sock\n", "/tmp/fabric-ab12.sock"},
		{"socket of a sibling directory", "state\t/home/u/state\nsocket\t/home/u/state-other/control.sock\n", "state-other"},
		{"colon in a path", plainReport + "folder\t/home/u/a:b\n", "colon"},
		{"quote in a path", plainReport + "folder\t/home/u/a\"b\n", "quote"},
		{"relative path", plainReport + "root\trelative/root\n", "not an absolute path"},
		{"unknown kind", plainReport + "device\t/dev/sda\n", "unknown line"},
		{"empty report", "", "no state directory"},
	}
	for _, c := range cases {
		out, stderr, err := sandboxLines(t, c.report, "/home/u", "/home/u/.local/bin/fabric")
		if err == nil {
			t.Errorf("%s: accepted:\n%s", c.name, out)
			continue
		}
		if out != "" {
			t.Errorf("%s: refused but still printed unit lines:\n%s", c.name, out)
		}
		if !strings.Contains(stderr, c.wantErr) {
			t.Errorf("%s: message does not mention %q:\n%s", c.name, c.wantErr, stderr)
		}
	}
	// A directory named with -w is checked like a declared one.
	if out, _, err := sandboxLines(t, plainReport, "/home/u", "/home/u/.local/bin/fabric", "/srv/a:b"); err == nil {
		t.Errorf("accepted a -w path with a colon:\n%s", out)
	}
}
