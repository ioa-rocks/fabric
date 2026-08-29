package daemon

import (
	"context"
	"log"
	"sync"
	"time"

	"ioa.rocks/fabric/astral"
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
	gens map[string]chan struct{} // name → closed-and-replaced on every append
}

func newWaiters() *waiters { return &waiters{gens: map[string]chan struct{}{}} }

// chanFor returns the current generation channel for name.
func (w *waiters) chanFor(name string) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, ok := w.gens[name]
	if !ok {
		ch = make(chan struct{})
		w.gens[name] = ch
	}
	return ch
}

// notify releases everyone parked on name.
func (w *waiters) notify(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ch, ok := w.gens[name]; ok {
		close(ch)
		delete(w.gens, name)
	}
}

// waitLocal parks until name (hosted here) has pending mail or timeout.
// An active wait counts as activity: a parked waiter keeps its ephemeral
// reply subject from idling out under it.
func (d *Daemon) waitLocal(ctx context.Context, name string, timeout time.Duration) (Woke, error) {
	_ = d.Store.Touch(name)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		// Take the generation *before* checking, so an append between the
		// check and the park cannot be missed.
		ch := d.wake.chanFor(name)
		n, err := d.Store.Pending(name)
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

// Wait parks until name has pending mail (wherever it is hosted) or
// timeout. Remote waits ride one stream per wait; the host's deadline is
// timeout plus slack.
func (d *Daemon) Wait(ctx context.Context, name string, timeout time.Duration) (Woke, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if _, ok, err := d.Store.Subject(name); err != nil {
		return "", err
	} else if ok {
		return d.waitLocal(ctx, name, timeout)
	}
	host, ok, err := d.Store.Host(name)
	if err != nil || !ok {
		return "", orUnknown(err)
	}
	resp, err := d.remoteWithin(host, request{Op: OpWait, Name: name, LeaseNS: int64(timeout)}, timeout+5*time.Second)
	if err != nil {
		return "", err
	}
	return Woke(resp.Woke), nil
}

// --- monitors ---

// Heartbeat extends an entity's liveness lease on the host of
// subject:<entity> (an entity with no placed inbox is monitored here).
func (d *Daemon) Heartbeat(entity string, ttl time.Duration) error {
	host, remote, err := d.entityHost(entity)
	if err != nil {
		return err
	}
	if !remote {
		_, err := d.Store.Heartbeat(entity, ttl)
		return err
	}
	_, err = d.remote(host, request{Op: OpHeartbeat, Name: entity, LeaseNS: int64(ttl)})
	return err
}

// Watch subscribes a watcher subject to entity's death notices.
func (d *Daemon) Watch(entity, watcher string) error {
	host, remote, err := d.entityHost(entity)
	if err != nil {
		return err
	}
	if !remote {
		return d.Store.Watch(entity, watcher)
	}
	_, err = d.remote(host, request{Op: OpWatch, Name: entity, Consumer: watcher})
	return err
}

func (d *Daemon) entityHost(entity string) (host string, remote bool, err error) {
	inbox := "subject:" + entity
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

func (d *Daemon) monitorLoop() {
	t := time.NewTicker(MonitorInterval)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		}
		d.sweepMonitors()
		d.sweepExpired()
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
	names, err := d.Store.IdleExpired(now)
	if err != nil {
		log.Printf("astral: expiry sweep: %v", err)
		return
	}
	for _, name := range names {
		if err := d.Store.Expire(name); err != nil {
			log.Printf("astral: expiring %s: %v", name, err)
			continue
		}
		log.Printf("astral: subject %s expired (idle)", name)
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
		notice := astral.DeathNotice(l.Entity, l.Gen, time.Now().UnixNano())
		ok := true
		for _, w := range l.Watchers {
			if _, err := d.Append(w, notice); err != nil {
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
