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
// '-at <dir>' names the blob store root a full or cache placement writes
// to (placement-record memo: the root is local to this device and never
// gossiped); 'default' returns to the device's own store. Mounts are a
// surface over the store, not a placement, so they are declared
// separately ('fabric bucket mount').

func cmdPlace(args []string) error {
	fs := flag.NewFlagSet("place", flag.ExitOnError)
	pth := pathFlags(fs)
	rescan := fs.Bool("rescan", false, "ask the daemon to scan the folder replica now")
	at := fs.String("at", "", "blob store root for a full/cache placement (absolute dir, or 'default')")
	pos := parse(fs, args, -1)
	usage := "usage: fabric bucket place <bucket> [full|cache|none | folder <dir>] [-at <dir>|default] [-rescan]"
	if len(pos) < 1 || len(pos) > 3 {
		return errors.New(usage)
	}
	ref := pos[0]
	st, err := openStore(pth)
	if err != nil {
		return err
	}
	defer st.Close()
	bkt, err := findBucket(st, ref)
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*pth.store) // folder operations need the daemon

	if len(pos) > 1 {
		mode := pos[1]
		switch {
		case mode == "folder":
			if len(pos) != 3 {
				return errors.New(usage)
			}
			if *at != "" {
				return errors.New("-at applies to full/cache placements; a folder replica keeps its blobs beside the folder")
			}
			dir, err := filepath.Abs(pos[2])
			if err != nil {
				return err
			}
			if cl == nil {
				return fmt.Errorf("folders are served by the daemon: is 'fabric up' running?")
			}
			if bkt.Folder == dir {
				fmt.Printf("already placed: %s is kept at %s\n", bkt.Name, dir)
			} else {
				if bkt.Folder != "" {
					if err := cl.RemoveFolder(bkt.Folder); err != nil {
						return err
					}
				}
				info, err := cl.AddFolder(dir, bkt.ID)
				if err != nil {
					return err
				}
				fmt.Printf("placed: bucket %q is kept at %s — the daemon syncs it from now on\n", info.Name, info.Dir)
			}
		case mode == "full" || mode == "cache" || mode == "none":
			if len(pos) != 2 {
				return errors.New(usage)
			}
			if bkt.Folder != "" {
				if cl == nil {
					return fmt.Errorf("%s is a folder replica; withdrawing it needs the daemon ('fabric up')", bkt.Name)
				}
				if err := cl.RemoveFolder(bkt.Folder); err != nil {
					return err
				}
				fmt.Printf("folder declaration withdrawn: %s (the directory is untouched)\n", bkt.Folder)
			}
			var root *string
			if *at != "" {
				resolvedRoot := *at
				if resolvedRoot != "default" {
					if resolvedRoot, err = filepath.Abs(resolvedRoot); err != nil {
						return err
					}
				}
				root = &resolvedRoot
			}
			if err := st.Place(bkt.ID, mode, root); err != nil {
				return err
			}
			fmt.Printf("placed: %s -> %s\n", bkt.Name, mode)
			if root != nil && *root != "default" {
				fmt.Printf("blobs for this bucket now land in %s; any already in the default store stay there, readable\n", *root)
			}
			if mode == store.SubFull {
				fmt.Println("missing blobs will be fetched as peers are reachable")
			}
		default:
			return fmt.Errorf("unknown placement %q — full, cache, none, or folder <dir>", mode)
		}
		if bkt, err = findBucket(st, ref); err != nil {
			return err
		}
	}

	if *rescan {
		if cl == nil || bkt.Folder == "" {
			return fmt.Errorf("-rescan needs a folder replica served by the running daemon")
		}
		if err := cl.RescanFolder(bkt.Folder); err != nil {
			return err
		}
		fmt.Printf("rescan requested: %s\n", bkt.Folder)
	}

	// The detailed view.
	mode := bkt.Sub
	if mode == "" {
		mode = "none (catalog + index only)"
	}
	if bkt.Folder != "" {
		mode = "folder " + bkt.Folder
	} else if bkt.Root != "" {
		mode += " at " + bkt.Root
	}
	fmt.Printf("%s  %s: %s — holding %d/%d blobs\n", bkt.ID[:16], bkt.Name, mode, bkt.Held, bkt.Objects)
	if cl == nil {
		return nil
	}
	if bkt.Folder != "" {
		if infos, err := cl.Folders(); err == nil {
			for _, folderInfo := range infos {
				if folderInfo.Dir == bkt.Folder {
					printFolder(folderInfo)
				}
			}
		}
	}
	if mounts, err := cl.Mounts(); err == nil {
		var mine []daemon.MountInfo
		for _, mount := range mounts {
			if mount.Bucket == bkt.ID {
				mine = append(mine, mount)
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
	for _, bkt := range buckets {
		if bkt.Name == ref || strings.HasPrefix(bkt.ID, ref) {
			return bkt, nil
		}
	}
	return daemon.BucketInfo{}, fmt.Errorf("no bucket matches %q", ref)
}

func printFolder(folderInfo daemon.FolderInfo) {
	state := "closed"
	switch {
	case folderInfo.Open && folderInfo.Available:
		state = "open"
	case folderInfo.Open:
		state = "unavailable (directory or marker missing)"
	}
	fmt.Printf("folder %s  %s\n", folderInfo.Dir, state)
	if folderInfo.Open {
		last := "never"
		if folderInfo.LastScan != 0 {
			last = time.Unix(0, folderInfo.LastScan).Format(time.RFC3339)
		}
		fmt.Printf("    files %d  pending down %d  pending up %d  conflicts %d  held %d  excluded repos %d  ignored %d  last scan %s\n",
			folderInfo.Files, folderInfo.PendingDown, folderInfo.PendingUp, folderInfo.Conflicts, folderInfo.Held, folderInfo.Excluded, folderInfo.Ignored, last)
	}
	if folderInfo.Error != "" {
		fmt.Printf("    error: %s\n", folderInfo.Error)
	}
}

// PrintFolders renders folder state lines (shared with 'fabric circle status').
func PrintFolders(infos []daemon.FolderInfo) {
	for _, folderInfo := range infos {
		name := folderInfo.Name
		if name == "" {
			name = folderInfo.Bucket[:min(16, len(folderInfo.Bucket))]
		}
		fmt.Printf("  %s  ", name)
		printFolder(folderInfo)
	}
}
