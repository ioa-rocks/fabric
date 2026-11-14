package daemon

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"ioa.rocks/fabric/astral"
)

// Spread placement (ADR 0015): a shared queue hosted by several nodes at
// once, each with its own journal and no coordination between them.
// Publishers pick one host and fall over to the next; consumers claim from
// all of them. Delivery stays at-least-once: an event that reached two
// hosts (a publisher that failed over after a lost answer) is handed out
// by both.

// route is where a ref's journal lives when it is not (only) on this node.
type route struct {
	single string             // the one remote host of a single-host name
	spread []astral.Placement // the remote hosts of a spread name, ranked
}

func (r route) known() bool { return r.single != "" || len(r.spread) > 0 }

func (d *Daemon) remoteRoute(ref astral.Ref) (route, error) {
	host, ok, err := d.Store.Host(ref)
	if err != nil {
		return route{}, err
	}
	if ok {
		return route{single: host}, nil
	}
	hosts, err := d.Store.SpreadHosts(ref)
	return route{spread: hosts}, err
}

// passesOn reports whether a host's refusal means "not me, try the next
// host" rather than "this publish is wrong": the host is draining, or it
// no longer has the name and its announcement is stale.
func passesOn(refusal string) bool {
	return strings.Contains(refusal, astral.ErrDraining.Error()) ||
		strings.Contains(refusal, astral.ErrUnknownSubject.Error())
}

// appendRemote publishes to a remote host of ref. For a spread name it
// walks the hosts in rank order and stops at the first that accepts, or at
// the first real refusal. unreachable is true when nothing refused and
// nothing accepted, the one case in which parking the event can help.
func (d *Daemon) appendRemote(rt route, ref astral.Ref, ev astral.Event, pr *astral.Principal, wantReply bool) (resp response, host string, unreachable bool, err error) {
	req := request{Op: OpAppend, Circle: ref.Circle, Name: ref.Name, Event: ev, Principal: pr, Reply: wantReply}
	if rt.single != "" {
		resp, err = d.remote(rt.single, req)
		return resp, rt.single, err != nil && resp.Err == "", err
	}
	tried := 0
	for _, h := range rt.spread {
		if h.Draining {
			continue
		}
		tried++
		resp, err = d.remote(h.Host, req)
		if err == nil {
			return resp, h.Host, false, nil
		}
		if resp.Err != "" && !passesOn(resp.Err) {
			return resp, h.Host, false, err
		}
		log.Printf("astral: %s on %s: %v; trying the next host", ref, d.hostLabel(h.Host), err)
	}
	if tried == 0 {
		err = fmt.Errorf("%w (every host of it)", astral.ErrDraining)
		return response{Err: err.Error()}, "", false, err
	}
	return response{}, "", true, fmt.Errorf("no host of %s is reachable: %w", ref, err)
}

// claimSpread claims from every host of a spread name until n events are
// in hand. The starting host rotates, so events stranded on a host that
// publishers rarely pick are not starved by a busy first choice. One host
// answering is enough; the others may be down.
func (d *Daemon) claimSpread(pr *astral.Principal, ref astral.Ref, local bool, consumer string, lease time.Duration, n int) ([]astral.Claimed, error) {
	hosts, err := d.Store.SpreadHosts(ref)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		n = 1
	}
	sources := make([]string, 0, len(hosts)+1)
	if local {
		sources = append(sources, "")
	}
	for _, h := range hosts {
		sources = append(sources, h.Host)
	}
	if len(sources) == 0 {
		return nil, astral.ErrUnknownSubject
	}
	start := int(d.rotate.Add(1)) % len(sources)
	var out []astral.Claimed
	var last error
	answered := false
	for i := range sources {
		if len(out) >= n {
			break
		}
		host := sources[(start+i)%len(sources)]
		var got []astral.Claimed
		if host == "" {
			got, err = d.Store.ClaimAs(ref, d.localConsumer(pr, consumer), lease, n-len(out), holdOf("", d.localPrincipal(pr), pr))
		} else {
			var resp response
			resp, err = d.remote(host, request{Op: OpClaim, Circle: ref.Circle, Name: ref.Name, Consumer: consumer, LeaseNS: int64(lease), N: n - len(out), Principal: pr})
			got = resp.Claimed
			if err == nil {
				d.learnReplyRoutes(ref.Circle, got, host)
			}
		}
		if err != nil {
			last = err
			continue
		}
		answered = true
		for _, c := range got {
			d.origins.put(ref, c.Event.ID, host)
		}
		out = append(out, got...)
	}
	if !answered {
		return nil, last
	}
	return out, nil
}

// ackSpread acknowledges on the host the event was claimed from. If that
// is no longer known (this daemon restarted in between), the host that has
// the event takes the ack.
func (d *Daemon) ackSpread(pr *astral.Principal, ref astral.Ref, local bool, consumer, eventID string) error {
	try := func(host string) error {
		if host == "" {
			if err := d.localAuthorize(pr, OpAck, ref, eventID, consumer, ""); err != nil {
				return err
			}
			return d.Store.Ack(ref, d.localConsumer(pr, consumer), eventID)
		}
		_, err := d.remote(host, request{Op: OpAck, Circle: ref.Circle, Name: ref.Name, Consumer: consumer, EventID: eventID, Principal: pr})
		return err
	}
	if origin, ok := d.origins.get(ref, eventID); ok && (origin != "" || local) {
		err := try(origin)
		if err == nil {
			d.origins.drop(ref, eventID)
		}
		return err
	}
	hosts, err := d.Store.SpreadHosts(ref)
	if err != nil {
		return err
	}
	last := error(astral.ErrUnknownSubject)
	if local {
		if last = try(""); last == nil {
			return nil
		}
	}
	for _, h := range hosts {
		if last = try(h.Host); last == nil {
			return nil
		}
	}
	return last
}

// waitSpread parks on every host of a spread name at once and returns at
// the first one that has mail. A wait only signals; the claim that follows
// goes through claimSpread, so cancelling the other waits loses nothing.
func (d *Daemon) waitSpread(ctx context.Context, pr *astral.Principal, ref astral.Ref, local bool, timeout time.Duration) (Woke, error) {
	hosts, err := d.Store.SpreadHosts(ref)
	if err != nil {
		return "", err
	}
	if !local && len(hosts) == 0 {
		return "", astral.ErrUnknownSubject
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		woke Woke
		err  error
	}
	results := make(chan result, len(hosts)+1)
	waiting := 0
	if local {
		waiting++
		go func() {
			woke, err := d.waitHeld(ctx, ref, timeout, holdOf("", d.localPrincipal(pr), pr))
			results <- result{woke, err}
		}()
	}
	for _, h := range hosts {
		waiting++
		go func(host string) {
			resp, err := d.remoteCtx(ctx, host, request{Op: OpWait, Circle: ref.Circle, Name: ref.Name, LeaseNS: int64(timeout), Principal: pr}, timeout+5*time.Second)
			results <- result{Woke(resp.Woke), err}
		}(h.Host)
	}
	answered := false
	var last error
	for ; waiting > 0; waiting-- {
		r := <-results
		if r.err == nil && r.woke == WokeMail {
			cancel()
			for waiting--; waiting > 0; waiting-- {
				<-results
			}
			return WokeMail, nil
		}
		if r.err == nil {
			answered = true
		} else {
			last = r.err
		}
	}
	if answered {
		return WokeTimeout, nil
	}
	return "", last
}

// SetSpread turns spread placement on or off for a subject hosted here and
// tells the members.
func (d *Daemon) SetSpread(ref astral.Ref, on bool) error {
	if err := d.Store.SetSpread(ref, on); err != nil {
		return err
	}
	go d.announceRegistry()
	return nil
}

// Drain starts (or ends) emptying this host's journal of a spread name:
// it refuses new events, keeps serving claims, and says so in its
// announcement so publishers stop choosing it. Remove the subject once
// its pending count reaches zero.
func (d *Daemon) Drain(ref astral.Ref, on bool) error {
	m, ok, err := d.Store.Subject(ref)
	if err != nil {
		return err
	}
	if !ok {
		return astral.ErrUnknownSubject
	}
	if on && !m.Spread {
		return fmt.Errorf("astral: %s has no other host to take its events; drain applies to a spread subject", ref)
	}
	if err := d.Store.SetDraining(ref, on); err != nil {
		return err
	}
	go d.announceRegistry()
	return nil
}

// hostingFlags reports which of refs (hosted here) are spread, and which
// of those are draining: the two lists that travel beside a registry
// announcement.
func (d *Daemon) hostingFlags(refs []astral.Ref) (spread, draining []astral.Ref) {
	for _, ref := range refs {
		m, ok, err := d.Store.Subject(ref)
		if err != nil || !ok || !m.Spread {
			continue
		}
		spread = append(spread, ref)
		if m.Draining {
			draining = append(draining, ref)
		}
	}
	return spread, draining
}

// announcedOf rebuilds a peer's announcement from its wire lists. A flag
// for a ref that is not in refs is ignored: refs is what passed the host
// check.
func announcedOf(refs, spread, draining []astral.Ref) []astral.Announced {
	isSpread := make(map[astral.Ref]bool, len(spread))
	for _, ref := range spread {
		isSpread[ref] = true
	}
	isDraining := make(map[astral.Ref]bool, len(draining))
	for _, ref := range draining {
		isDraining[ref] = true
	}
	out := make([]astral.Announced, len(refs))
	for i, ref := range refs {
		out[i] = astral.Announced{Ref: ref, Spread: isSpread[ref], Draining: isSpread[ref] && isDraining[ref]}
	}
	return out
}

// originTable remembers which host a claimed event of a spread name came
// from, so its ack goes back there. It is a cache: losing it costs one
// round of asking each host.
type originTable struct {
	mu sync.Mutex
	m  map[originKey]originAt
}

type originKey struct {
	ref astral.Ref
	id  string
}

type originAt struct {
	host string
	at   time.Time
}

func newOriginTable() *originTable { return &originTable{m: map[originKey]originAt{}} }

func (t *originTable) put(ref astral.Ref, id, host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= 4096 {
		// Leases end after MaxLease; an older entry answers nothing.
		cutoff := time.Now().Add(-2 * astral.MaxLease)
		for k, v := range t.m {
			if v.at.Before(cutoff) {
				delete(t.m, k)
			}
		}
	}
	t.m[originKey{ref, id}] = originAt{host, time.Now()}
}

func (t *originTable) get(ref astral.Ref, id string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[originKey{ref, id}]
	return v.host, ok
}

func (t *originTable) drop(ref astral.Ref, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, originKey{ref, id})
}
