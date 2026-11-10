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
	policy, err := st.Policy(pos[0])
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		printPolicy(policy)
		return nil
	}
	if pos[1] != "set" || len(pos) < 3 {
		return fmt.Errorf("usage: fabric bucket policy <bucket> set key=value ... (keys: copies trash_days ignore symlinks nested_repos hold_min_count hold_min_percent)")
	}
	// Signing happens here, where the passphrase prompt is — with the key
	// of the circle that owns this bucket.
	owner, err := bucketOwner(st, pos[0])
	if err != nil {
		return err
	}
	ownerCircle, err := pth.openOwner(owner)
	if err != nil {
		return err
	}
	pass, err := Passphrase()
	if err != nil {
		return err
	}
	priv, err := ownerCircle.Unlock(pass)
	if err != nil {
		return err
	}
	var applyErr error
	raw, err := store.SignPolicyRevision(priv, policy, func(next *bucket.Policy) {
		for _, kv := range pos[2:] {
			key, val, ok := strings.Cut(kv, "=")
			if !ok {
				applyErr = fmt.Errorf("expected key=value, got %q", kv)
				return
			}
			if err := setPolicyField(next, key, val); err != nil {
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
	policy, err = st.SetPolicy(pos[0], raw)
	if err != nil {
		return err
	}
	fmt.Printf("policy v%d installed\n", policy.Version)
	printPolicy(policy)
	return nil
}

func setPolicyField(policy *bucket.Policy, key, val string) error {
	num := func() (int, error) {
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("%s: %q is not a number", key, val)
		}
		return parsed, nil
	}
	var err error
	switch key {
	case "copies":
		policy.Copies, err = num()
	case "trash_days":
		policy.TrashDays, err = num()
	case "hold_min_count":
		policy.HoldMinCount, err = num()
	case "hold_min_percent":
		policy.HoldMinPercent, err = num()
	case "symlinks":
		policy.Symlinks = val
	case "nested_repos":
		policy.NestedRepos = val
	case "ignore":
		// Comma-separated patterns replace the list; "" clears it.
		policy.Ignore = nil
		for _, pat := range strings.Split(val, ",") {
			if pat = strings.TrimSpace(pat); pat != "" {
				policy.Ignore = append(policy.Ignore, pat)
			}
		}
	default:
		return fmt.Errorf("unknown policy key %q", key)
	}
	return err
}

func printPolicy(policy bucket.Policy) {
	minCount, minPercent, enabled := policy.Hold()
	hold := "off"
	if enabled {
		hold = fmt.Sprintf(">= %d objects and >= %d%% of the bucket", minCount, minPercent)
	}
	fmt.Printf("version       %d\ncopies        %d\ntrash_days    %d\nsymlinks      %s\nnested_repos  %s\nhold          %s\nignore        %s\n",
		policy.Version, policy.Copies, policy.TrashDays, policy.SymlinkMode(), policy.NestedRepoMode(), hold, strings.Join(policy.Ignore, ", "))
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
	for _, obj := range objs {
		fmt.Printf("%s  %s  deleted %s\n", obj.ID[:12], obj.Name, time.Unix(0, obj.Modified).Format(time.RFC3339))
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
	obj, err := st.Restore(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("restored %s (%s)\n", obj.ID[:12], obj.Name)
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
	for _, conflict := range cs {
		fmt.Printf("%s  %s\n    kept:  %.12s  %d bytes  %s\n    copy:  %s  %.12s  %d bytes  by %s\n",
			conflict.Object.ID[:12], conflict.Object.Name, conflict.Object.Blob, conflict.Object.Size, time.Unix(0, conflict.Object.Modified).Format(time.RFC3339),
			conflict.Copy.Name, conflict.Copy.Blob, conflict.Copy.Size, conflict.Copy.By)
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
	obj, err := st.Resolve(pos[0], pos[1])
	if err != nil {
		return err
	}
	fmt.Printf("resolved %s (%s) in favor of %.12s\n", obj.ID[:12], obj.Name, obj.Blob)
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
		var count int
		switch pos[1] {
		case "accept":
			count, err = st.AcceptHeld(pos[0])
			if err == nil {
				fmt.Printf("accepted: %d object(s) deleted (recoverable from trash)\n", count)
			}
		case "reject":
			count, err = st.RejectHeld(pos[0])
			if err == nil {
				fmt.Printf("rejected: %d object(s) kept; the deleting device converges on the restore\n", count)
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
	for _, entry := range list {
		fmt.Printf("%s  %s  from %s  since %s\n", entry.ID[:12], entry.Name, entry.From, time.Unix(0, entry.FirstSeen).Format(time.RFC3339))
	}
	fmt.Printf("%d deletion(s) held — fabric bucket held <bucket> accept|reject\n", len(list))
	return nil
}

// bucketOwner resolves a bucket (by ID prefix or name) to its owner DID.
func bucketOwner(st store_, ref string) (string, error) {
	infos, err := st.Buckets()
	if err != nil {
		return "", err
	}
	for _, bkt := range infos {
		if bkt.Name == ref || (len(ref) >= 6 && strings.HasPrefix(bkt.ID, ref)) {
			return bkt.Owner, nil
		}
	}
	return "", fmt.Errorf("no bucket %q", ref)
}
