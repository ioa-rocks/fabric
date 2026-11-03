package daemon

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/statement"
)

// Wake (contract rule 2): the wake channel may be cheap and lossy because
// the journal is the truth. A consumer parks in `wait` — locally over the
// control socket, or remotely over a stream to the host — and is released
// when mail lands or its timeout elapses (the timer wake). A dropped
// stream, a missed edge, a restart: the consumer simply claims again. No
// gossip is involved; point-to-point wait over an authenticated stream is
// the whole mechanism.

// MonitorInterval is how often lapsed heartbeat leases are swept.
// Variable so tests can shrink it.
var MonitorInterval = time.Second

// Woke says why a wait returned.
type Woke string

const (
	WokeMail    Woke = "mail"
	WokeTimeout Woke = "timeout"
)

type waiters struct {
	mu   sync.Mutex
	gens map[astral.Ref]chan struct{} // ref → closed-and-replaced on every append
}

func newWaiters() *waiters { return &waiters{gens: map[astral.Ref]chan struct{}{}} }

// chanFor returns the current generation channel for ref.
func (w *waiters) chanFor(ref astral.Ref) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, ok := w.gens[ref]
	if !ok {
		ch = make(chan struct{})
		w.gens[ref] = ch
	}
	return ch
}

// notify releases everyone parked on ref.
func (w *waiters) notify(ref astral.Ref) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ch, ok := w.gens[ref]; ok {
		close(ch)
		delete(w.gens, ref)
	}
}

// waitTable is every parked wait with its holder, so a revocation can end
// the ones whose authority died.
type waitTable struct {
	mu   sync.Mutex
	next int
	by   map[int]*parkedWait
}

type parkedWait struct {
	ref    astral.Ref
	hold   astral.Hold
	cancel context.CancelCauseFunc
}

func newWaitTable() *waitTable { return &waitTable{by: map[int]*parkedWait{}} }

func (w *waitTable) add(p *parkedWait) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.next++
	w.by[w.next] = p
	return w.next
}

func (w *waitTable) remove(id int) {
	w.mu.Lock()
	delete(w.by, id)
	w.mu.Unlock()
}

func (w *waitTable) all() []*parkedWait {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*parkedWait, 0, len(w.by))
	for _, p := range w.by {
		out = append(out, p)
	}
	return out
}

// errRevoked ends a wait whose holder lost its authority.
var errRevoked = errors.New("astral: authority revoked while waiting")

// waitHeld is waitLocal registered under a holder: a revocation push can
// end it early.
func (d *Daemon) waitHeld(ctx context.Context, ref astral.Ref, timeout time.Duration, hold astral.Hold) (Woke, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	id := d.waits.add(&parkedWait{ref: ref, hold: hold, cancel: cancel})
	defer d.waits.remove(id)
	woke, err := d.waitLocal(ctx, ref, timeout)
	if err != nil && errors.Is(context.Cause(ctx), errRevoked) {
		return "", errRevoked
	}
	return woke, err
}

// waitLocal parks until ref (hosted here) has pending mail or timeout.
// An active wait counts as activity: a parked waiter keeps its ephemeral
// reply subject from idling out under it.
func (d *Daemon) waitLocal(ctx context.Context, ref astral.Ref, timeout time.Duration) (Woke, error) {
	_ = d.Store.Touch(ref)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		// Take the generation *before* checking, so an append between the
		// check and the park cannot be missed.
		ch := d.wake.chanFor(ref)
		n, err := d.Store.Pending(ref)
		if err != nil {
			return "", err
		}
		if n > 0 {
			return WokeMail, nil
		}
		select {
		case <-ch:
		case <-deadline.C:
			return WokeTimeout, nil
		case <-ctx.Done():
			return WokeTimeout, ctx.Err()
		}
	}
}

// Wait parks until ref has pending mail (wherever it is hosted) or
// timeout. Remote waits ride one stream per wait; the host's deadline is
// timeout plus slack.
func (d *Daemon) Wait(ctx context.Context, pr *astral.Principal, ref astral.Ref, timeout time.Duration) (Woke, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if m, ok, err := d.Store.Subject(ref); err != nil {
		return "", err
	} else if ok {
		if m.IsReplySlot() {
			if err := d.replyAccess(m, d.principalLabel(pr)); err != nil {
				return "", err
			}
		} else if err := d.localAuthorize(pr, OpWait, ref, "", "", ""); err != nil {
			return "", err
		}
		return d.waitHeld(ctx, ref, timeout, holdOf("", pr))
	}
	host, ok, err := d.Store.Host(ref)
	if err != nil || !ok {
		return "", orUnknown(err)
	}
	resp, err := d.remoteWithin(host, request{Op: OpWait, Circle: ref.Circle, Name: ref.Name, LeaseNS: int64(timeout), Principal: pr}, timeout+5*time.Second)
	if err != nil {
		d.dropDeadRoute(ref, resp)
		return "", err
	}
	return Woke(resp.Woke), nil
}

// --- monitors ---

// Heartbeat extends an entity's liveness lease on the host of
// subject:<entity> in the entity's circle (an entity with no placed inbox
// is monitored here).
func (d *Daemon) Heartbeat(pr *astral.Principal, entity astral.Ref, ttl time.Duration) error {
	host, remote, err := d.entityHost(entity)
	if err != nil {
		return err
	}
	if !remote {
		if err := d.localAuthorize(pr, OpHeartbeat, entity, "", "", ""); err != nil {
			return err
		}
		_, err := d.Store.Heartbeat(entity, ttl)
		return err
	}
	_, err = d.remote(host, request{Op: OpHeartbeat, Circle: entity.Circle, Name: entity.Name, LeaseNS: int64(ttl), Principal: pr})
	return err
}

// Watch subscribes a watcher subject (same circle) to entity's death
// notices.
func (d *Daemon) Watch(pr *astral.Principal, entity astral.Ref, watcher string) error {
	host, remote, err := d.entityHost(entity)
	if err != nil {
		return err
	}
	if !remote {
		if err := d.localAuthorize(pr, OpWatch, entity, "", watcher, ""); err != nil {
			return err
		}
		return d.Store.WatchAs(entity, astral.Ref{Circle: entity.Circle, Name: watcher}, holdOf("", pr))
	}
	_, err = d.remote(host, request{Op: OpWatch, Circle: entity.Circle, Name: entity.Name, Consumer: watcher, Principal: pr})
	return err
}

func (d *Daemon) entityHost(entity astral.Ref) (host string, remote bool, err error) {
	inbox := astral.Ref{Circle: entity.Circle, Name: "subject:" + entity.Name}
	if _, ok, err := d.Store.Subject(inbox); err != nil || ok {
		return "", false, err
	}
	host, ok, err := d.Store.Host(inbox)
	if err != nil || !ok {
		return "", false, err
	}
	return host, true, nil
}

// TombstoneKeep is how long an expired subject's marker outlives it, so a
// late replier still gets "expired" rather than "unknown". Variable so
// tests can shrink it.
var TombstoneKeep = 24 * time.Hour

// RecheckInterval is how often held leases, watches and waits are
// re-checked against their holder's authority regardless of pushes (an
// expired chain has no push). Variable so tests can shrink it.
var RecheckInterval = 30 * time.Second

func (d *Daemon) monitorLoop() {
	t := time.NewTicker(MonitorInterval)
	defer t.Stop()
	rc := time.NewTicker(RecheckInterval)
	defer rc.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		case <-rc.C:
			d.recheck()
			continue
		}
		d.sweepMonitors()
		d.sweepExpired()
	}
}

// stillHolds re-verifies one holder for verb on ref: nil when it still may,
// an error when its authority is gone (revoked, expired, no longer a
// member). A holder whose peer is not connected right now cannot be
// re-checked and is left to its own timeout.
func (d *Daemon) stillHolds(h astral.Hold, ref astral.Ref, verb string) error {
	if d.Fabric == nil || d.Fabric.Circle == nil {
		return nil
	}
	p := d.Fabric.Host.ID()
	if h.Peer != "" {
		var err error
		if p, err = peer.Decode(h.Peer); err != nil {
			return nil
		}
		if d.Fabric.Host.Network().Connectedness(p) != network.Connected {
			return nil
		}
	}
	want := statement.Want{Sub: ref.Circle, Res: statement.Resource{Kind: statement.KindSubject, Name: ref.Name}, Verb: verb, Now: time.Now()}
	if h.Key == "" {
		if h.Peer == "" {
			return nil // the device itself, local trust
		}
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
		defer cancel()
		return d.Fabric.Circle.Verify(ctx, p, want)
	}
	comp, err := d.Fabric.Circle.Present(p, h.Chain)
	if err != nil {
		return err
	}
	return d.Fabric.Circle.VerifyPresented(p, comp.AuthLeafID(), h.Key, want)
}

// recheck releases every lease, drops every watch and ends every parked
// wait whose holder no longer verifies (memo §12.24: push-invalidate, so
// another worker can reclaim at once and a revoked key's wait returns).
func (d *Daemon) recheck() {
	if !d.begin() {
		return
	}
	defer d.end()
	d.recheckMu.Lock()
	defer d.recheckMu.Unlock()
	now := time.Now()
	if leases, err := d.Store.Leases(now); err == nil {
		for _, l := range leases {
			if err := d.stillHolds(l.Hold, l.Ref, statement.VerbClaim); err != nil {
				log.Printf("astral: lease on %s by %s released: %v", l.Ref, l.Consumer, err)
				_ = d.Store.Release(l.Ref, l.EventID)
			}
		}
	}
	if ws, err := d.Store.Watches(); err == nil {
		for _, w := range ws {
			inbox := astral.Ref{Circle: w.Entity.Circle, Name: "subject:" + w.Entity.Name}
			if err := d.stillHolds(w.Hold, inbox, statement.VerbRead); err != nil {
				log.Printf("astral: watch on %s by %s dropped: %v", w.Entity, w.Watcher, err)
				_ = d.Store.Unwatch(w.Entity, w.Watcher)
			}
		}
	}
	for _, pw := range d.waits.all() {
		if err := d.stillHolds(pw.hold, pw.ref, statement.VerbClaim); err != nil {
			pw.cancel(errRevoked)
		}
	}
}

// sweepExpired self-destructs subjects whose idle TTL elapsed, leaving
// tombstones, and eventually drops the tombstones themselves.
func (d *Daemon) sweepExpired() {
	if !d.begin() {
		return
	}
	defer d.end()
	now := time.Now()
	refs, err := d.Store.IdleExpired(now)
	if err != nil {
		log.Printf("astral: expiry sweep: %v", err)
		return
	}
	for _, ref := range refs {
		if err := d.Store.Expire(ref); err != nil {
			log.Printf("astral: expiring %s: %v", ref, err)
			continue
		}
		log.Printf("astral: subject %s expired (idle)", ref)
	}
	if err := d.Store.SweepTombstones(now, TombstoneKeep); err != nil {
		log.Printf("astral: tombstone sweep: %v", err)
	}
}

// sweepMonitors casts a death notice for every lapsed lease to each of its
// watchers, then marks the generation notified. Append is idempotent by
// the notice's deterministic ID, so a crash between the two steps only
// causes a harmless duplicate cast.
func (d *Daemon) sweepMonitors() {
	if !d.begin() {
		return
	}
	defer d.end()
	lapses, err := d.Store.Lapsed(time.Now())
	if err != nil {
		log.Printf("astral: monitor sweep: %v", err)
		return
	}
	for _, l := range lapses {
		notice := astral.DeathNotice(l.Entity.Name, l.Gen, time.Now().UnixNano())
		ok := true
		for _, w := range l.Watchers {
			if _, err := d.Append(nil, w, notice); err != nil {
				log.Printf("astral: death notice for %s → %s: %v", l.Entity, w, err)
				ok = false
			}
		}
		if ok {
			if err := d.Store.MarkNotified(l.Entity, l.Gen); err != nil {
				log.Printf("astral: mark notified %s: %v", l.Entity, err)
			}
		}
	}
}
