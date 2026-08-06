package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const deployInspect = `set -eu
scope=system
if [ "$(systemctl show fabric.service -p LoadState --value 2>/dev/null || true)" != loaded ]; then
  scope=user
  [ "$(systemctl --user show fabric.service -p LoadState --value 2>/dev/null || true)" = loaded ] || { echo "no fabric.service found" >&2; exit 1; }
fi
ctl=systemctl
[ "$scope" = system ] || ctl="systemctl --user"
pid=$($ctl show fabric.service -p MainPID --value)
[ "$pid" -gt 0 ] || { echo "fabric.service is not running" >&2; exit 1; }
bin=$(readlink -f "/proc/$pid/exe")
printf '%s\n%s\n%s\n%s\n' "$scope" "$HOME" "$pid" "$bin"`

func cmdDeploy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fabric deploy <ssh-host> [ssh-host...]")
	}
	local, err := os.Executable()
	if err != nil {
		return err
	}
	for _, host := range args {
		if err := deployHost(host, local); err != nil {
			return fmt.Errorf("deploy %s: %w", host, err)
		}
	}
	return nil
}

func deployHost(host, local string) error {
	fmt.Printf("== %s\n", host)
	info, err := sshOutput(host, deployInspect)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(info), "\n")
	if len(lines) != 4 {
		return fmt.Errorf("unexpected service inspection response %q", info)
	}
	scope, home, oldPID, oldBin := lines[0], lines[1], lines[2], lines[3]
	target := home + "/.local/bin/fabric"
	legacy := home + "/fabric"
	if oldBin != target && oldBin != legacy {
		return fmt.Errorf("service executable %s is not the supported legacy path %s; reinstall its unit with -b %s", oldBin, legacy, target)
	}

	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	upload := "set -eu; mkdir -p " + shellQuote(home+"/.local/bin") +
		"; cat > " + shellQuote(target+".next") +
		"; chmod 755 " + shellQuote(target+".next") +
		"; mv -f " + shellQuote(target+".next") + " " + shellQuote(target)
	if err := sshInput(host, upload, f); err != nil {
		return err
	}
	if oldBin != target {
		if err := sshInput(host, "ln -sfn "+shellQuote(target)+" "+shellQuote(oldBin), nil); err != nil {
			return fmt.Errorf("migrate old executable path: %w", err)
		}
	}
	fmt.Printf("   installed %s\n", target)

	if err := sshInput(host, "kill -9 "+shellQuote(oldPID), nil); err != nil {
		return err
	}
	ctl := "systemctl"
	if scope == "user" {
		ctl = "systemctl --user"
	}
	for i := 0; i < 20; i++ {
		time.Sleep(time.Second)
		pid, _ := sshOutput(host, ctl+" show fabric.service -p MainPID --value")
		pid = strings.TrimSpace(pid)
		if n, _ := strconv.Atoi(pid); n > 0 && pid != oldPID {
			if _, err := sshOutput(host, shellQuote(target)+" status"); err != nil {
				return fmt.Errorf("daemon restarted as pid %s but health check failed: %w", pid, err)
			}
			fmt.Printf("   daemon restarted (pid %s -> %s), health check passed\n", oldPID, pid)
			return nil
		}
	}
	return fmt.Errorf("daemon did not restart; inspect its journal")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func sshOutput(host, remote string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("ssh", host, remote)
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func sshInput(host, remote string, in io.Reader) error {
	cmd := exec.Command("ssh", host, remote)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, os.Stdout, os.Stderr
	return cmd.Run()
}
