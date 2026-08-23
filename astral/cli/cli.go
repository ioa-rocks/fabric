// Package cli is `fabric astral …`: a plane client over the subsystem's
// control socket. It is deliberately verb-shaped like the contract —
// append / claim / ack / set / get — plus the host-side declarations
// (mailbox, host) that stand in for registration until the registry exists.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
)

const usage = `usage: fabric astral <command> [flags] [args]

  status                               hosted names, placements, outbox, connected members
  mailbox <name> [-accepts k1,k2]      host a mailbox:<entity> or queue:<name> here
  host <name> <member>                 record that <member> hosts <name> ("" clears)
  append <name> [-kind user] [-source tool] [-id id] [-ref artifact] [-reply target] [-corr id] <content|->
  claim <name> [-consumer me] [-lease 30] [-n 1]
  ack <name> <event-id> [-consumer me]
  set <register:entity/key> <value>
  get <register:entity/key>

Every command accepts -state <dir> (default ` + "`" + `%s` + "`" + `).
`

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(os.Stderr, usage, daemon.DefaultPath())
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "status":
		err = cmdStatus(rest)
	case "mailbox":
		err = cmdMailbox(rest)
	case "host":
		err = cmdHost(rest)
	case "append":
		err = cmdAppend(rest)
	case "claim":
		err = cmdClaim(rest)
	case "ack":
		err = cmdAck(rest)
	case "set":
		err = cmdSet(rest)
	case "get":
		err = cmdGet(rest)
	default:
		fmt.Fprintf(os.Stderr, "astral: unknown command %q\n", cmd)
		fmt.Fprintf(os.Stderr, usage, daemon.DefaultPath())
		return 2
	}
	if err != nil {
		msg := err.Error()
		if !strings.HasPrefix(msg, "astral:") {
			msg = "astral: " + msg
		}
		fmt.Fprintln(os.Stderr, msg)
		return 1
	}
	return 0
}

// flags builds a flag set with -state and interleaved parsing: flags are
// valid before and after positionals.
func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("astral "+name, flag.ExitOnError)
	st := fs.String("state", daemon.DefaultPath(), "astral state directory")
	return fs, st
}

func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	return pos
}

func cmdStatus(args []string) error {
	fs, st := flags("status")
	parse(fs, args)
	s, err := daemon.NewClient(*st).Status()
	if err != nil {
		return err
	}
	fmt.Printf("astral %s  state %s\n", s.Version, s.Path)
	if s.Mesh {
		fmt.Printf("member %s  connected: %s\n", s.Member, strings.Join(s.Connected, " "))
	} else {
		fmt.Println("solo (no mesh attached)")
	}
	if len(s.Hosted) > 0 {
		fmt.Println("hosted here:")
		for _, h := range s.Hosted {
			acc := "any kind"
			if len(h.Accepts) > 0 {
				acc = strings.Join(h.Accepts, ",")
			}
			fmt.Printf("  %-32s pending %-4d accepts %s\n", h.Name, h.Pending, acc)
		}
	}
	if len(s.Placed) > 0 {
		fmt.Println("placed elsewhere:")
		for n, h := range s.Placed {
			fmt.Printf("  %-32s @ %s\n", n, h)
		}
	}
	if s.Outbox > 0 {
		fmt.Printf("outbox: %d parked cast(s)\n", s.Outbox)
	}
	return nil
}

func cmdMailbox(args []string) error {
	fs, st := flags("mailbox")
	accepts := fs.String("accepts", "", "comma-separated kinds accepted (empty = any)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: mailbox <name> [-accepts k1,k2]")
	}
	var kinds []string
	if *accepts != "" {
		kinds = strings.Split(*accepts, ",")
	}
	return daemon.NewClient(*st).Declare(pos[0], kinds)
}

func cmdHost(args []string) error {
	fs, st := flags("host")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: host <name> <member>")
	}
	return daemon.NewClient(*st).SetHost(pos[0], pos[1])
}

func cmdAppend(args []string) error {
	fs, st := flags("append")
	kind := fs.String("kind", "user", "event kind")
	source := fs.String("source", "cli", "source tool (member label is stamped by the daemon)")
	id := fs.String("id", "", "event id (derived when empty)")
	ref := fs.String("ref", "", "payload artifact reference")
	reply := fs.String("reply", "", "reply target")
	corr := fs.String("corr", "", "correlation id")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: append <name> [flags] <content|->")
	}
	content := pos[1]
	if content == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		content = strings.TrimRight(string(b), "\n")
	}
	eid, fresh, err := daemon.NewClient(*st).Append(pos[0], astral.Event{
		ID: *id, Kind: *kind, Source: *source, Content: content,
		PayloadRef: *ref, ReplyTarget: *reply, CorrelationID: *corr,
	})
	if err != nil {
		return err
	}
	if fresh {
		fmt.Println(eid)
	} else {
		fmt.Printf("%s (duplicate)\n", eid)
	}
	return nil
}

func cmdClaim(args []string) error {
	fs, st := flags("claim")
	consumer := fs.String("consumer", "cli", "consumer identity")
	lease := fs.Int("lease", 30, "lease seconds")
	n := fs.Int("n", 1, "max events")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: claim <name> [-consumer me] [-lease 30] [-n 1]")
	}
	c, err := daemon.NewClient(*st).Claim(pos[0], *consumer, *lease, *n)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, cl := range c {
		if err := enc.Encode(cl.Event); err != nil {
			return err
		}
	}
	return nil
}

func cmdAck(args []string) error {
	fs, st := flags("ack")
	consumer := fs.String("consumer", "cli", "consumer identity")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: ack <name> <event-id> [-consumer me]")
	}
	return daemon.NewClient(*st).Ack(pos[0], *consumer, pos[1])
}

func cmdSet(args []string) error {
	fs, st := flags("set")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: set <register:entity/key> <value>")
	}
	return daemon.NewClient(*st).Set(pos[0], pos[1])
}

func cmdGet(args []string) error {
	fs, st := flags("get")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: get <register:entity/key>")
	}
	r, ok, err := daemon.NewClient(*st).Get(pos[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: unset", pos[0])
	}
	fmt.Println(r.Value)
	return nil
}
