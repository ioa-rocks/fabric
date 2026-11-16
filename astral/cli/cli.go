// Package cli is `fabric astral …`: a plane client over the subsystem's
// control socket. It is deliberately verb-shaped like the contract —
// append / claim / ack / set / get — plus the host-side declarations
// (subject, host); host is retained as a manual registry override.
package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/astral/daemon"
	fabricdaemon "ioa.rocks/fabric/daemon"
	"ioa.rocks/fabric/state"
)

const usage = `usage: fabric astral <command> [flags] [args]

  status                               hosted subjects, placements, outbox, connected members
  subject <subject:name> [-delivery exclusive|shared] [-accepts k1,k2] [-idle 10m] [-max 100] [-spread]
                                       -idle self-destructs after inactivity; -max caps appends;
                                       -spread lets other nodes host the same shared queue too:
                                       declare it on each host (-spread=false turns it off here)
  drain <name> [-off]                  this host of a spread queue takes no new events and keeps
                                       serving claims; rm it once status shows nothing pending
  rm <name>                            remove a hosted subject and its journal
  host <name> <member|peer-id>         record that a node hosts <name> ("" clears)
  append <name> [-kind user] [-source tool] [-id id] [-ref artifact] [-corr id] [-reply [-wait 30]] <content|->
                                       -reply makes it a request: the host keeps the reply with it, and
                                       the request id printed is the handle for 'reply'; with -wait N the
                                       reply is awaited and printed here instead
  reply <name> <request-id> [-wait 30] [-keep]
                                       print the reply to a request you published with -reply, waiting
                                       up to N seconds; it is released once printed unless -keep
  claim <name> [-consumer me] [-lease 30] [-n 1] [-wait 0]
                                       -wait N parks up to N seconds for mail first
  complete <name> <request-id> [-kind result] [-source tool] [-ref artifact] <content|->
                                       finish a request you claimed: its reply is signed and recorded and
                                       the request acknowledged, in one step
  heartbeat <entity> [-ttl 30]         extend <entity>'s liveness lease
  watch <entity> <watcher-subject>     cast a system death notice there when the lease lapses
  ack <name> <event-id> [-consumer me]
  set <register:entity/key> <value>
  get <register:entity/key>
  key new -res subject:a[,subject:b|*] -verbs claim[,publish,…] [-exp 720h] [-label worker] -out agent.key
                                       mint a sub-key under this device's admission in -circle
  key list                             sub-keys this device issued
  key revoke <id-prefix>               revoke an issued sub-key (reaches members online now)
  worker claim|wait|append|complete|ack|heartbeat -key worker.key [-gate addr] <name> …
                                       act as a grantee against a listed gate, no daemon
                                       (the key file from 'fabric circle grant new')

Every command accepts -state <dir> (default ` + "`" + `%s` + "`" + `),
-circle <did> — the circle the name belongs to (default: this node's home
circle) — and -key <file>: act as that sub-key (its circle applies).
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
	case "subject":
		err = cmdSubject(rest)
	case "drain":
		err = cmdDrain(rest)
	case "rm":
		err = cmdRm(rest)
	case "host":
		err = cmdHost(rest)
	case "append":
		err = cmdAppend(rest)
	case "claim":
		err = cmdClaim(rest)
	case "complete":
		err = cmdComplete(rest)
	case "reply":
		err = cmdReply(rest)
	case "ack":
		err = cmdAck(rest)
	case "heartbeat":
		err = cmdHeartbeat(rest)
	case "watch":
		err = cmdWatch(rest)
	case "set":
		err = cmdSet(rest)
	case "get":
		err = cmdGet(rest)
	case "key":
		err = cmdKey(rest)
	case "worker":
		err = cmdWorker(rest)
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

// flags builds a flag set with -state and -circle and interleaved parsing:
// flags are valid before and after positionals.
func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("astral "+name, flag.ExitOnError)
	st := fs.String("state", daemon.DefaultPath(), "astral state directory")
	fs.String("circle", "", "circle DID the name belongs to (default: this node's home circle)")
	fs.String("key", "", "act as the sub-key in this key file (fabric astral key new)")
	return fs, st
}

// client builds the control-socket client for the parsed flags.
func client(fs *flag.FlagSet, st *string) *daemon.Client {
	cl := daemon.NewClient(*st).In(fs.Lookup("circle").Value.String())
	if path := fs.Lookup("key").Value.String(); path != "" {
		signer, err := astral.LoadKeyFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "astral:", err)
			os.Exit(1)
		}
		cl = cl.WithKey(signer)
	}
	return cl
}

// cmdKey mints, lists and revokes sub-keys through the fabric daemon, which
// holds the device key the sub-key chains under.
func cmdKey(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: key new|list|revoke")
	}
	switch args[0] {
	case "new":
		return cmdKeyNew(args[1:])
	case "list":
		return cmdKeyList(args[1:])
	case "revoke":
		return cmdKeyRevoke(args[1:])
	}
	return fmt.Errorf("usage: key new|list|revoke")
}

func fabricClient(fs *flag.FlagSet) *fabricdaemon.Client {
	dir, _ := state.Open(fs.Lookup("fabric-state").Value.String())
	return fabricdaemon.NewClient(dir)
}

func cmdKeyNew(args []string) error {
	fs := flag.NewFlagSet("astral key new", flag.ExitOnError)
	fs.String("fabric-state", state.DefaultPath(), "fabric state directory (the device key lives there)")
	circle := fs.String("circle", "", "circle the sub-key acts in (default: this node's home circle)")
	res := fs.String("res", "", "comma-separated subjects it may touch, or * (required)")
	verbs := fs.String("verbs", "", "comma-separated verbs: publish,claim,ack,read,host (required)")
	exp := fs.Duration("exp", 30*24*time.Hour, "validity")
	label := fs.String("label", "", "a label for 'key list'")
	out := fs.String("out", "", "key file to write (required; mode 0600)")
	fs.Parse(args)
	if *res == "" || *verbs == "" || *out == "" {
		return fmt.Errorf("usage: key new -res <subjects|*> -verbs <verbs> -out <file> [-circle did] [-exp 720h] [-label l]")
	}
	k, err := fabricClient(fs).IssueKey(fabricdaemon.IssueKeyBody{
		Circle: *circle, Res: strings.Split(*res, ","), Verbs: strings.Split(*verbs, ","),
		ValidityS: int64(exp.Seconds()), Label: *label,
	})
	if err != nil {
		return err
	}
	if err := astral.WriteKeyFile(*out, astral.KeyFile{
		ID: k.ID, DID: k.DID, Circle: k.Circle, Res: k.Res, Verbs: k.Verbs, Exp: k.Exp,
		Seed: base64.StdEncoding.EncodeToString(k.Seed), Chain: base64.StdEncoding.EncodeToString(k.Chain),
	}); err != nil {
		return err
	}
	fmt.Printf("sub-key %s  %s\n  circle %s\n  %s on %s until %s\n  written to %s — the seed exists nowhere else\n",
		k.ID[:8], k.DID, k.Circle, strings.Join(k.Verbs, ","), strings.Join(k.Res, ","), time.Unix(k.Exp, 0).Format("2006-01-02"), *out)
	return nil
}

func cmdKeyList(args []string) error {
	fs := flag.NewFlagSet("astral key list", flag.ExitOnError)
	fs.String("fabric-state", state.DefaultPath(), "fabric state directory")
	fs.Parse(args)
	ks, err := fabricClient(fs).Keys()
	if err != nil {
		return err
	}
	if len(ks) == 0 {
		fmt.Println("no sub-keys issued by this device")
		return nil
	}
	for _, k := range ks {
		state := "live"
		switch {
		case k.Revoked != 0:
			state = "REVOKED " + time.Unix(k.Revoked, 0).Format("2006-01-02")
		case time.Now().Unix() > k.Exp:
			state = "expired"
		}
		fmt.Printf("%s  %-10s %s on %s  circle %s…  until %s  %s\n", k.ID[:8], k.Label, strings.Join(k.Verbs, ","), strings.Join(k.Res, ","), k.Circle[:min(len(k.Circle), 16)], time.Unix(k.Exp, 0).Format("2006-01-02"), state)
	}
	return nil
}

func cmdKeyRevoke(args []string) error {
	fs := flag.NewFlagSet("astral key revoke", flag.ExitOnError)
	fs.String("fabric-state", state.DefaultPath(), "fabric state directory")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: key revoke <id-prefix>")
	}
	if err := fabricClient(fs).RevokeKey(fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("revoked; members online now were told, the rest learn on their next circle exchange")
	return nil
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
	s, err := client(fs, st).Status()
	if err != nil {
		return err
	}
	fmt.Printf("astral %s  state %s\n", s.Version, s.Path)
	if s.Mesh {
		fmt.Printf("member %s  connected: %s\n", s.Member, strings.Join(s.Connected, " "))
	} else {
		fmt.Println("solo (no mesh attached)")
	}
	fmt.Printf("home circle %s\n", s.Home)
	if len(s.Hosted) > 0 {
		fmt.Println("hosted here:")
		for _, h := range s.Hosted {
			acc := "any kind"
			if len(h.Accepts) > 0 {
				acc = strings.Join(h.Accepts, ",")
			}
			name := h.Name
			if h.Circle != s.Home {
				name = h.Name + " @ " + h.Circle
			}
			if h.Spread {
				acc += "  spread"
			}
			if h.Draining {
				acc += "  draining"
			}
			if h.Calls > 0 {
				acc += fmt.Sprintf("  replies kept %d", h.Calls)
			}
			fmt.Printf("  %-32s pending %-4d accepts %s\n", name, h.Pending, acc)
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

func cmdSubject(args []string) error {
	fs, st := flags("subject")
	accepts := fs.String("accepts", "", "comma-separated kinds accepted (empty = any)")
	delivery := fs.String("delivery", string(astral.DeliveryExclusive), "exclusive or shared")
	idle := fs.Duration("idle", 0, "self-destruct after this much inactivity (0 = never)")
	maxEvents := fs.Int("max", 0, "cap on total appended events (0 = unlimited)")
	spread := fs.Bool("spread", false, "let other nodes host this shared queue too (declare it on each); -spread=false turns it off here")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: subject <subject:name> [-delivery exclusive|shared] [-accepts k1,k2] [-idle 10m] [-max 100] [-spread]")
	}
	var kinds []string
	if *accepts != "" {
		kinds = strings.Split(*accepts, ",")
	}
	cl := client(fs, st)
	spreadSet := false
	fs.Visit(func(f *flag.Flag) { spreadSet = spreadSet || f.Name == "spread" })
	if spreadSet {
		if *idle > 0 || *maxEvents > 0 {
			return fmt.Errorf("-spread does not combine with -idle or -max")
		}
		if *spread {
			return cl.DeclareSpread(pos[0], kinds)
		}
		return cl.SetSpread(pos[0], astral.Delivery(*delivery), kinds, false)
	}
	if *idle > 0 || *maxEvents > 0 {
		return cl.DeclareExpiring(pos[0], astral.Delivery(*delivery), kinds, *idle, *maxEvents)
	}
	return cl.Declare(pos[0], astral.Delivery(*delivery), kinds)
}

func cmdDrain(args []string) error {
	fs, st := flags("drain")
	off := fs.Bool("off", false, "end the drain: accept new events again")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: drain <name> [-off]")
	}
	return client(fs, st).Drain(pos[0], !*off)
}

func cmdRm(args []string) error {
	fs, st := flags("rm")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: rm <name>")
	}
	return client(fs, st).Remove(pos[0])
}

func cmdHost(args []string) error {
	fs, st := flags("host")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: host <name> <member|peer-id>")
	}
	return client(fs, st).SetHost(pos[0], pos[1])
}

func cmdAppend(args []string) error {
	fs, st := flags("append")
	kind := fs.String("kind", "user", "event kind")
	source := fs.String("source", "cli", "source tool (member label is stamped by the daemon)")
	id := fs.String("id", "", "event id (derived when empty)")
	ref := fs.String("ref", "", "payload artifact reference")
	reply := fs.Bool("reply", false, "a request: the host keeps the reply with it (read it with 'reply')")
	wait := fs.Int("wait", 0, "with -reply: wait up to this many seconds and print the reply")
	corr := fs.String("corr", "", "correlation id: the event this one refers to")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: append <name> [flags] <content|->")
	}
	content, err := contentArg(pos[1])
	if err != nil {
		return err
	}
	ev := astral.Event{ID: *id, Kind: *kind, Source: *source, Content: content, PayloadRef: *ref, CorrelationID: *corr}
	cl := client(fs, st)
	if *reply {
		eid, err := cl.AppendRequest(pos[0], ev)
		if err != nil {
			return err
		}
		if *wait <= 0 {
			fmt.Println(eid)
			return nil
		}
		return printReply(cl, pos[0], eid, *wait, false)
	}
	eid, fresh, err := cl.Append(pos[0], ev)
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
	wait := fs.Int("wait", 0, "park up to this many seconds for mail before claiming")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: claim <name> [-consumer me] [-lease 30] [-n 1] [-wait 0]")
	}
	cl := client(fs, st)
	if *wait > 0 {
		if _, err := cl.Wait(pos[0], *wait); err != nil {
			return err
		}
	}
	c, err := cl.Claim(pos[0], *consumer, *lease, *n)
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

// contentArg reads an event's content: the argument, or stdin for "-".
func contentArg(arg string) (string, error) {
	if arg != "-" {
		return arg, nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// printReply waits for the reply to a request, prints it and, unless keep,
// releases it: once it is on stdout the host need not hold it.
func printReply(cl *daemon.Client, name, requestID string, waitS int, keep bool) error {
	reply, err := cl.Outcome(name, requestID, waitS)
	if err != nil {
		return err
	}
	if reply == nil {
		return fmt.Errorf("no reply to %s yet (fabric astral reply %s %s -wait N)", requestID, name, requestID)
	}
	if err := json.NewEncoder(os.Stdout).Encode(reply); err != nil {
		return err
	}
	if keep {
		return nil
	}
	return cl.Release(name, requestID)
}

func cmdReply(args []string) error {
	fs, st := flags("reply")
	wait := fs.Int("wait", 0, "wait up to this many seconds for the reply")
	keep := fs.Bool("keep", false, "leave the reply at the host (read it again later)")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: reply <name> <request-id> [-wait 30] [-keep]")
	}
	return printReply(client(fs, st), pos[0], pos[1], *wait, *keep)
}

func cmdComplete(args []string) error {
	fs, st := flags("complete")
	kind := fs.String("kind", "result", "reply kind (result, error, …)")
	source := fs.String("source", "cli", "source tool (member label is stamped by the daemon)")
	ref := fs.String("ref", "", "payload artifact reference")
	pos := parse(fs, args)
	if len(pos) != 3 {
		return fmt.Errorf("usage: complete <name> <request-id> [-kind result] <content|->")
	}
	content, err := contentArg(pos[2])
	if err != nil {
		return err
	}
	delivered, err := client(fs, st).Complete(pos[0], pos[1], astral.Event{Kind: *kind, Source: *source, Content: content, PayloadRef: *ref})
	if err != nil {
		return err
	}
	if !delivered {
		fmt.Println("acknowledged; nobody is waiting for the reply")
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
	return client(fs, st).Ack(pos[0], *consumer, pos[1])
}

func cmdSet(args []string) error {
	fs, st := flags("set")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: set <register:entity/key> <value>")
	}
	return client(fs, st).Set(pos[0], pos[1])
}

func cmdGet(args []string) error {
	fs, st := flags("get")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: get <register:entity/key>")
	}
	r, ok, err := client(fs, st).Get(pos[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: unset", pos[0])
	}
	fmt.Println(r.Value)
	return nil
}

func cmdHeartbeat(args []string) error {
	fs, st := flags("heartbeat")
	ttl := fs.Int("ttl", 30, "lease seconds")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: heartbeat <entity> [-ttl 30]")
	}
	return client(fs, st).Heartbeat(pos[0], *ttl)
}

func cmdWatch(args []string) error {
	fs, st := flags("watch")
	pos := parse(fs, args)
	if len(pos) != 2 {
		return fmt.Errorf("usage: watch <entity> <watcher-subject>")
	}
	return client(fs, st).Watch(pos[0], pos[1])
}

// cmdWorker is the grantee's side: a key file with a grant and gate hints,
// a direct connection to a listed gate, no daemon or state directory.
func cmdWorker(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: worker claim|wait|append|complete|ack|heartbeat -key worker.key [-gate addr] <name> …")
	}
	verb, rest := args[0], args[1:]
	fs := flag.NewFlagSet("astral worker "+verb, flag.ExitOnError)
	keyPath := fs.String("key", "", "the grantee's key file (required)")
	var gates stringList
	fs.Var(&gates, "gate", "listed gate multiaddr (repeatable; default: the key file's hints)")
	consumer := fs.String("consumer", "worker", "consumer identity")
	lease := fs.Int("lease", 30, "lease seconds (claim)")
	n := fs.Int("n", 1, "max events (claim)")
	wait := fs.Int("wait", 0, "park up to this many seconds for mail (claim/wait)")
	kind := fs.String("kind", "result", "event kind (append, complete)")
	source := fs.String("source", "worker", "source tool (append, complete)")
	corr := fs.String("corr", "", "correlation id: the event this one refers to (append)")
	ttl := fs.Int("ttl", 30, "lease seconds (heartbeat)")
	pos := parse(fs, rest)
	if *keyPath == "" || len(pos) < 1 {
		return fmt.Errorf("usage: worker %s -key worker.key [-gate addr] <name> …", verb)
	}
	signer, err := astral.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	w, err := daemon.DialGate(ctx, signer, gates...)
	if err != nil {
		return err
	}
	defer w.Close()
	name := pos[0]
	switch verb {
	case "claim":
		if *wait > 0 {
			if _, err := w.Wait(ctx, name, time.Duration(*wait)*time.Second); err != nil {
				return err
			}
		}
		c, err := w.Claim(ctx, name, *consumer, time.Duration(*lease)*time.Second, *n)
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
	case "wait":
		woke, err := w.Wait(ctx, name, time.Duration(*wait)*time.Second)
		if err != nil {
			return err
		}
		fmt.Println(woke)
		return nil
	case "append":
		if len(pos) != 2 {
			return fmt.Errorf("usage: worker append -key worker.key <name> [-corr event-id] <content|->")
		}
		content, err := contentArg(pos[1])
		if err != nil {
			return err
		}
		fresh, err := w.Append(ctx, name, astral.Event{Kind: *kind, Source: *source, Content: content, CorrelationID: *corr})
		if err != nil {
			return err
		}
		if !fresh {
			fmt.Println("(duplicate)")
		}
		return nil
	case "complete":
		if len(pos) != 3 {
			return fmt.Errorf("usage: worker complete -key worker.key <name> <request-id> [-kind result] <content|->")
		}
		content, err := contentArg(pos[2])
		if err != nil {
			return err
		}
		delivered, err := w.Complete(ctx, name, pos[1], astral.Event{Kind: *kind, Source: *source, Content: content})
		if err != nil {
			return err
		}
		if !delivered {
			fmt.Println("acknowledged; nobody is waiting for the reply")
		}
		return nil
	case "ack":
		if len(pos) != 2 {
			return fmt.Errorf("usage: worker ack -key worker.key <name> <event-id>")
		}
		return w.Ack(ctx, name, *consumer, pos[1])
	case "heartbeat":
		return w.Heartbeat(ctx, name, time.Duration(*ttl)*time.Second)
	}
	return fmt.Errorf("worker: unknown verb %q", verb)
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }
