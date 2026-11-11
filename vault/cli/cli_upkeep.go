package cli

import (
	"flag"
	"fmt"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// upkeepClient is the running daemon: reclaim and scrub work on its open
// stores and stop its transfers from racing them, so neither runs without
// it.
func upkeepClient(pth paths, command string) (*daemon.Client, error) {
	client := daemon.TryClient(*pth.store)
	if client == nil {
		return nil, fmt.Errorf("fabric bucket %s needs the running daemon (fabric up); none answers on %s", command, daemon.SocketPath(*pth.store))
	}
	return client, nil
}

func cmdReclaim(args []string) error {
	fs := flag.NewFlagSet("reclaim", flag.ExitOnError)
	pth := pathFlags(fs)
	dryRun := fs.Bool("dry-run", false, "count what would be removed, remove nothing")
	if pos := parse(fs, args, -1); len(pos) != 0 {
		return fmt.Errorf("usage: fabric bucket reclaim [-dry-run]")
	}
	client, err := upkeepClient(pth, "reclaim")
	if err != nil {
		return err
	}
	report, err := client.Reclaim(*dryRun)
	if err != nil {
		return fmt.Errorf("nothing removed: %w", err)
	}
	verb := "removed"
	if report.DryRun {
		verb = "would remove"
	}
	fmt.Printf("%s %d blobs, %s, that no bucket on this device retains\n", verb, report.Blobs, formatSize(report.Bytes))
	if report.Young > 0 {
		fmt.Printf("%d more arrived within the last hour and are left for a later pass\n", report.Young)
	}
	return nil
}

func cmdScrub(args []string) error {
	fs := flag.NewFlagSet("scrub", flag.ExitOnError)
	pth := pathFlags(fs)
	pos := parse(fs, args, -1)
	if len(pos) > 1 {
		return fmt.Errorf("usage: fabric bucket scrub [bucket]")
	}
	client, err := upkeepClient(pth, "scrub")
	if err != nil {
		return err
	}
	bucketRef := ""
	if len(pos) == 1 {
		bucketRef = pos[0]
	}
	started := time.Now()
	report, err := client.Scrub(bucketRef)
	if err != nil {
		return err
	}
	scope := "this device"
	if report.Bucket != "" {
		scope = "bucket " + report.Bucket
	}
	fmt.Printf("%s: read back %d blobs, %s, in %s\n", scope, report.Checked, formatSize(report.Bytes), time.Since(started).Round(time.Second))
	if report.Stopped {
		fmt.Println("stopped before the end")
	}
	for _, finding := range report.Corrupt {
		fmt.Printf("damaged  %.12s  in %s — set aside; a clean copy is fetched where the placement is full\n", finding.Hash, finding.Store)
		for _, file := range finding.Files {
			fmt.Printf("         %s\n", file)
		}
	}
	if report.Unreadable > 0 {
		fmt.Printf("%d blobs could not be read and were left as they are (see the daemon log)\n", report.Unreadable)
	}
	for _, folder := range report.Folders {
		fmt.Printf("folder %s: %d files changed without their size or time changing — a failing disk, or a tool that restores timestamps. Nothing was touched:\n", folder.Dir, len(folder.Files))
		for _, file := range folder.Files {
			fmt.Printf("         %s\n", file)
		}
	}
	if len(report.Corrupt) == 0 && report.Unreadable == 0 && len(report.Folders) == 0 && !report.Stopped {
		fmt.Println("all of it is what it should be")
	}
	return nil
}
