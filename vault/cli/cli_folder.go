package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// Folder replicas are daemon-owned: these commands edit declarations and
// read state through the control socket.

func cmdFolder(args []string) error {
	fs := flag.NewFlagSet("folder", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 2 {
		return fmt.Errorf("usage: fabric vault folder <bucket> <dir>")
	}
	dir, err := filepath.Abs(pos[1])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("folders are served by the daemon: is 'fabric up' running?")
	}
	info, err := cl.AddFolder(dir, pos[0])
	if err != nil {
		return err
	}
	fmt.Printf("folder declared: bucket %q at %s — the daemon keeps it in sync from now on\n", info.Name, info.Dir)
	return nil
}

func cmdUnfolder(args []string) error {
	fs := flag.NewFlagSet("unfolder", flag.ExitOnError)
	statePath := stateFlag(fs)
	pos := parse(fs, args, -1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: fabric vault unfolder <dir>")
	}
	dir, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("folders are served by the daemon: is 'fabric up' running?")
	}
	if err := cl.RemoveFolder(dir); err != nil {
		return err
	}
	fmt.Printf("folder declaration removed: %s (the directory is untouched)\n", dir)
	return nil
}

func cmdFolders(args []string) error {
	fs := flag.NewFlagSet("folders", flag.ExitOnError)
	statePath := stateFlag(fs)
	rescan := fs.String("rescan", "", "ask the daemon to scan this folder now")
	parse(fs, args, -1)
	cl := daemon.TryClient(*statePath)
	if cl == nil {
		return fmt.Errorf("folders are served by the daemon: is 'fabric up' running?")
	}
	if *rescan != "" {
		dir, err := filepath.Abs(*rescan)
		if err != nil {
			return err
		}
		if err := cl.RescanFolder(dir); err != nil {
			return err
		}
		fmt.Printf("rescan requested: %s\n", dir)
	}
	infos, err := cl.Folders()
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		fmt.Println("no folders declared — declare one with: fabric vault folder <bucket> <dir>")
		return nil
	}
	for _, f := range infos {
		state := "closed"
		switch {
		case f.Open && f.Available:
			state = "open"
		case f.Open:
			state = "unavailable (directory or marker missing)"
		}
		fmt.Printf("%s  %q  %s\n", f.Dir, f.Name, state)
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
	return nil
}
