package cli

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/store"
)

// Commands for vault ADR 0001: policy, trash/restore, conflicts/resolve,
// held deletions.

func cmdPolicy(args []string) error {
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, 2)
	if len(pos) < 1 {
		return fmt.Errorf("usage: fabric bucket policy <bucket> [set key=value ...]")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	p, err := st.Policy(pos[0])
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		printPolicy(p)
		return nil
	}
	if pos[1] != "set" || len(pos) < 3 {
		return fmt.Errorf("usage: fabric bucket policy <bucket> set key=value ... (keys: copies trash_days ignore symlinks nested_repos hold_min_count hold_min_percent)")
	}
	// Signing happens here, where the passphrase prompt is.
	c, err := pth.openCircle()
	if err != nil {
		return err
	}
	pass, err := Passphrase()
	if err != nil {
		return err
	}
	priv, err := c.Unlock(pass)
	if err != nil {
		return err
	}
	var applyErr error
	raw, err := store.SignPolicyRevision(priv, p, func(np *bucket.Policy) {
		for _, kv := range pos[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				applyErr = fmt.Errorf("expected key=value, got %q", kv)
				return
			}
			if err := setPolicyField(np, k, v); err != nil {
				applyErr = err
				return
			}
		}
	})
	if applyErr != nil {
		return applyErr
	}
	if err != nil {
		return err
	}
	p, err = st.SetPolicy(pos[0], raw)
	if err != nil {
		return err
	}
	fmt.Printf("policy v%d installed\n", p.Version)
	printPolicy(p)
	return nil
}

func setPolicyField(p *bucket.Policy, k, v string) error {
	num := func() (int, error) {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s: %q is not a number", k, v)
		}
		return n, nil
	}
	var err error
	switch k {
	case "copies":
		p.Copies, err = num()
	case "trash_days":
		p.TrashDays, err = num()
	case "hold_min_count":
		p.HoldMinCount, err = num()
	case "hold_min_percent":
		p.HoldMinPercent, err = num()
	case "symlinks":
		p.Symlinks = v
	case "nested_repos":
		p.NestedRepos = v
	case "ignore":
		// Comma-separated patterns replace the list; "" clears it.
		p.Ignore = nil
		for _, pat := range strings.Split(v, ",") {
			if pat = strings.TrimSpace(pat); pat != "" {
				p.Ignore = append(p.Ignore, pat)
			}
		}
	default:
		return fmt.Errorf("unknown policy key %q", k)
	}
	return err
}

func printPolicy(p bucket.Policy) {
	minCount, minPercent, enabled := p.Hold()
	hold := "off"
	if enabled {
		hold = fmt.Sprintf(">= %d objects and >= %d%% of the bucket", minCount, minPercent)
	}
	fmt.Printf("version       %d\ncopies        %d\ntrash_days    %d\nsymlinks      %s\nnested_repos  %s\nhold          %s\nignore        %s\n",
		p.Version, p.Copies, p.TrashDays, p.SymlinkMode(), p.NestedRepoMode(), hold, strings.Join(p.Ignore, ", "))
}

func cmdTrash(args []string) error {
	fs := flag.NewFlagSet("trash", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric bucket trash <bucket>")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	objs, err := st.Trash(pos[0])
	if err != nil {
		return err
	}
	if len(objs) == 0 {
		fmt.Println("trash is empty")
		return nil
	}
	for _, o := range objs {
		fmt.Printf("%s  %s  deleted %s\n", o.ID[:12], o.Name, time.Unix(0, o.Modified).Format(time.RFC3339))
	}
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket restore <bucket> <object-ref>")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := st.Restore(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("restored %s (%s)\n", o.ID[:12], o.Name)
	return nil
}

func cmdConflicts(args []string) error {
	fs := flag.NewFlagSet("conflicts", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric bucket conflicts <bucket>")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	cs, err := st.Conflicts(pos[0])
	if err != nil {
		return err
	}
	if len(cs) == 0 {
		fmt.Println("no conflicts")
		return nil
	}
	for _, c := range cs {
		fmt.Printf("%s  %s\n    kept:  %.12s  %d bytes  %s\n    copy:  %s  %.12s  %d bytes  by %s\n",
			c.Object.ID[:12], c.Object.Name, c.Object.Blob, c.Object.Size, time.Unix(0, c.Object.Modified).Format(time.RFC3339),
			c.Copy.Name, c.Copy.Blob, c.Copy.Size, c.Copy.By)
	}
	fmt.Println("resolve in favor of the kept version: fabric bucket resolve <bucket> <object-ref>")
	return nil
}

func cmdResolve(args []string) error {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric bucket resolve <bucket> <object-ref>")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	o, err := st.Resolve(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("resolved %s (%s) in favor of %.12s\n", o.ID[:12], o.Name, o.Blob)
	return nil
}

func cmdHeld(args []string) error {
	fs := flag.NewFlagSet("held", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) < 1 || len(pos) > 2 {
		return fmt.Errorf("usage: fabric bucket held <bucket> [accept|reject]")
	}
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(pos) == 2 {
		var n int
		switch pos[1] {
		case "accept":
			n, err = st.AcceptHeld(pos[0])
			if err == nil {
				fmt.Printf("accepted: %d object(s) deleted (recoverable from trash)\n", n)
			}
		case "reject":
			n, err = st.RejectHeld(pos[0])
			if err == nil {
				fmt.Printf("rejected: %d object(s) kept; the deleting device converges on the restore\n", n)
			}
		default:
			err = fmt.Errorf("usage: fabric bucket held <bucket> [accept|reject]")
		}
		return err
	}
	list, err := st.Held(pos[0])
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no held deletions")
		return nil
	}
	for _, e := range list {
		fmt.Printf("%s  %s  from %s  since %s\n", e.ID[:12], e.Name, e.From, time.Unix(0, e.FirstSeen).Format(time.RFC3339))
	}
	fmt.Printf("%d deletion(s) held — fabric bucket held <bucket> accept|reject\n", len(list))
	return nil
}
