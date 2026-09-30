package cli

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

// Placement is how this device holds a bucket (bucket-model memo §5; pull,
// local, never remote): none (catalog + index only), cache, full, or a
// folder replica — a full placement kept as a real directory. One word
// per bucket per device; changing it from a folder to anything else
// withdraws the folder declaration (the directory is left as it is).
// Mounts are a surface over the store, not a placement, so they are
// declared separately ('fabric bucket mount').

func cmdPlace(args []string) error {
	fs := flag.NewFlagSet("place", flag.ExitOnError)
	p := pathFlags(fs)
	rescan := fs.Bool("rescan", false, "ask the daemon to scan the folder replica now")
	pos := parse(fs, args, -1)
	usage := "usage: fabric bucket place <bucket> [full|cache|none | folder <dir>] [-rescan]"
	if len(pos) < 1 || len(pos) > 3 {
		return errors.New(usage)
	}
	ref := pos[0]
	st, err := openStore(p)
	if err != nil {
		return err
	}
	defer st.Close()
	b, err := findBucket(st, ref)
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*p.store) // folder operations need the daemon

	if len(pos) > 1 {
		mode := pos[1]
		switch {
		case mode == "folder":
			if len(pos) != 3 {
				return errors.New(usage)
			}
			dir, err := filepath.Abs(pos[2])
			if err != nil {
				return err
			}
			if cl == nil {
				return fmt.Errorf("folders are served by the daemon: is 'fabric up' running?")
			}
			if b.Folder == dir {
				fmt.Printf("already placed: %s is kept at %s\n", b.Name, dir)
			} else {
				if b.Folder != "" {
					if err := cl.RemoveFolder(b.Folder); err != nil {
						return err
					}
				}
				info, err := cl.AddFolder(dir, b.ID)
				if err != nil {
					return err
				}
				fmt.Printf("placed: bucket %q is kept at %s — the daemon syncs it from now on\n", info.Name, info.Dir)
			}
		case mode == "full" || mode == "cache" || mode == "none":
			if len(pos) != 2 {
				return errors.New(usage)
			}
			if b.Folder != "" {
				if cl == nil {
					return fmt.Errorf("%s is a folder replica; withdrawing it needs the daemon ('fabric up')", b.Name)
				}
				if err := cl.RemoveFolder(b.Folder); err != nil {
					return err
				}
				fmt.Printf("folder declaration withdrawn: %s (the directory is untouched)\n", b.Folder)
			}
			if err := st.Sub(b.ID, mode); err != nil {
				return err
			}
			fmt.Printf("placed: %s -> %s\n", b.Name, mode)
			if mode == store.SubFull {
				fmt.Println("missing blobs will be fetched as peers are reachable")
			}
		default:
			return fmt.Errorf("unknown placement %q — full, cache, none, or folder <dir>", mode)
		}
		if b, err = findBucket(st, ref); err != nil {
			return err
		}
	}

	if *rescan {
		if cl == nil || b.Folder == "" {
			return fmt.Errorf("-rescan needs a folder replica served by the running daemon")
		}
		if err := cl.RescanFolder(b.Folder); err != nil {
			return err
		}
		fmt.Printf("rescan requested: %s\n", b.Folder)
	}

	// The detailed view.
	mode := b.Sub
	if mode == "" {
		mode = "none (catalog + index only)"
	}
	if b.Folder != "" {
		mode = "folder " + b.Folder
	}
	fmt.Printf("%s  %s: %s — holding %d/%d blobs\n", b.ID[:16], b.Name, mode, b.Held, b.Objects)
	if cl == nil {
		return nil
	}
	if b.Folder != "" {
		if infos, err := cl.Folders(); err == nil {
			for _, f := range infos {
				if f.Dir == b.Folder {
					printFolder(f)
				}
			}
		}
	}
	if mounts, err := cl.Mounts(); err == nil {
		var mine []daemon.MountInfo
		for _, m := range mounts {
			if m.Bucket == b.ID {
				mine = append(mine, m)
			}
		}
		if len(mine) > 0 {
			fmt.Println("mounts:")
			PrintMounts(mine)
		}
	}
	return nil
}

// findBucket resolves a name or ID prefix through the store's listing so
// the placement view has the per-device columns.
func findBucket(st store_, ref string) (daemon.BucketInfo, error) {
	buckets, err := st.Buckets()
	if err != nil {
		return daemon.BucketInfo{}, err
	}
	for _, b := range buckets {
		if b.Name == ref || strings.HasPrefix(b.ID, ref) {
			return b, nil
		}
	}
	return daemon.BucketInfo{}, fmt.Errorf("no bucket matches %q", ref)
}

func printFolder(f daemon.FolderInfo) {
	state := "closed"
	switch {
	case f.Open && f.Available:
		state = "open"
	case f.Open:
		state = "unavailable (directory or marker missing)"
	}
	fmt.Printf("folder %s  %s\n", f.Dir, state)
	if f.Open {
		last := "never"
		if f.LastScan != 0 {
			last = time.Unix(0, f.LastScan).Format(time.RFC3339)
		}
		fmt.Printf("    files %d  pending down %d  pending up %d  conflicts %d  held %d  excluded repos %d  ignored %d  last scan %s\n",
			f.Files, f.PendingDown, f.PendingUp, f.Conflicts, f.Held, f.Excluded, f.Ignored, last)
	}
	if f.Error != "" {
		fmt.Printf("    error: %s\n", f.Error)
	}
}

// PrintFolders renders folder state lines (shared with 'fabric circle status').
func PrintFolders(infos []daemon.FolderInfo) {
	for _, f := range infos {
		name := f.Name
		if name == "" {
			name = f.Bucket[:min(16, len(f.Bucket))]
		}
		fmt.Printf("  %s  ", name)
		printFolder(f)
	}
}
