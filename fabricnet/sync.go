package fabricnet

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"ioa.rocks/fabric/event"
	"ioa.rocks/fabric/internal/wire"
	"ioa.rocks/fabric/statement"

	"github.com/fxamacker/cbor/v2"
	libp2pevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
)

// Gossip protocol (spec §5 + connectivity-model memo). Two motions on one
// channel: anti-entropy — after every successful membership handshake (and
// on reconnect between known members) peers swap full state — and rumor
// mill: newly learned items are pushed on to other connected members.
// Members only; strangers are reset.
//
// SyncProtocolV2ID (step 5, slice C; memo l0-overlapping-circles §17) carries
// one set per circle *both* peers are verified in — the circle's device
// admissions and revocations as statements, plus the membership-event
// envelopes of the first circle (its admission path) — and the signed peer
// address records (the knowledge plane's WHERE, self-admitted by each
// device's key). A device never learns another circle's roster; a circle's
// set is relayed only to peers verified in it. The predecessors
// /fabric/sync/1 (events plus records, first circle only) and
// /fabric/events/1 were served for one release and retired in slice G
// (2026-11-06).
const SyncProtocolV2ID = "/fabric/sync/2"

// A log entry or address record is a few hundred bytes; even a large mesh
// with a deep history stays far under this.
const maxEventsWireSize = 1 << 20

const exchangeTimeout = 15 * time.Second

// addrRecordTTL bounds how long gossiped addresses are kept without being
// refreshed.
const addrRecordTTL = 48 * time.Hour

// recordRepublishInterval re-arms addrRecordTTL well inside the TTL. Connect
// time anti-entropy alone is not enough: a pair of nodes holding one stable
// long-lived connection never exchanges again, so nothing refreshes the
// addresses they hold for each other or for anyone else.
const recordRepublishInterval = 6 * time.Hour

// circleSet is one circle's anti-entropy set in a v2 exchange.
type circleSet struct {
	DID         string         `cbor:"did"`
	Roots       []string       `cbor:"roots,omitempty"` // the circle DID again (older binaries listed every root they honoured)
	Admissions  [][]byte       `cbor:"a,omitempty"`     // admissions, statement bytes (live and lapsed)
	Revocations [][]byte       `cbor:"r,omitempty"`     // statement bytes
	Handovers   [][]byte       `cbor:"h,omitempty"`     // the circle's key history, statement bytes, oldest first
	Events      []*event.Event `cbor:"e,omitempty"`     // membership-event envelopes (first circle only)
}

// syncPayloadV2 is one direction of a /fabric/sync/2 exchange.
type syncPayloadV2 struct {
	Circles []circleSet `cbor:"c,omitempty"`
	Records [][]byte    `cbor:"records,omitempty"`
}

// CircleHooks is what the circle service lends the gossip: this node's own
// admissions per circle (a roster holds other devices, not oneself), the live
// revocations per circle, and where a peer's revocations go (returns the
// ones that were new, for the relay).
type CircleHooks struct {
	OwnAdmissions func(circleDID string) [][]byte
	Revocations   func(circleDID string) [][]byte
	Ingest        func(from peer.ID, revocations [][]byte) (fresh [][]byte, err error)
}

// kickDelay debounces the anti-entropy kick a roster change triggers.
const kickDelay = 300 * time.Millisecond

// EventApplied is invoked once per newly learned event, in apply order,
// after it entered the log. The daemon uses it to update the member store,
// persist the log, and surface the spec-§5 notifications.
type EventApplied func(e *event.Event)

// EventSync gossips membership events and member address records.
type EventSync struct {
	h       host.Host
	log     *event.Log
	store   *MemberStore
	onApply EventApplied
	cab     peerstore.CertifiedAddrBook

	mu       sync.Mutex
	ownRec   []byte                // this host's latest signed peer record
	lastSeq  map[peer.ID]uint64    // highest record seq accepted per peer
	onRecord func(peer.ID, uint64) // newly accepted address version
	hooks    CircleHooks
	kicking  bool // a kick is scheduled

	stop []func()
}

// NewEventSync wires the gossip protocols onto the host. onApply may be
// nil. Call (*AuthService).SetOnAuthenticated with s.ExchangeAsync to
// complete the anti-entropy wiring — freshly authenticated peers exchange
// state; already-known members exchange on reconnect via the Connected
// notification here. The host's own signed address record is tracked via
// the event bus and re-pushed to connected members whenever it changes
// (network transitions).
func NewEventSync(h host.Host, log *event.Log, store *MemberStore, onApply EventApplied) *EventSync {
	cab, _ := h.Peerstore().(peerstore.CertifiedAddrBook)
	s := &EventSync{h: h, log: log, store: store, onApply: onApply, cab: cab, lastSeq: map[peer.ID]uint64{}}
	h.SetStreamHandler(SyncProtocolV2ID, s.handleSyncV2)
	// A roster change — a device admitted here, a verdict flipped — is
	// news for every peer in that circle: re-run anti-entropy with the
	// connected members shortly. Converges because a second exchange that
	// changes nothing kicks nothing.
	go func() {
		for range store.Watch() {
			s.kick()
		}
	}()
	nb := &network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
		p := c.RemotePeer()
		if s.store.IsMember(p, time.Now()) {
			s.ExchangeAsync(p)
		}
	}}
	h.Network().Notify(nb)
	s.stop = append(s.stop, func() { h.Network().StopNotify(nb) })
	s.watchOwnRecord()
	s.republishRecords()
	return s
}

// republishRecords re-pushes every record we hold to connected members on a
// timer, re-arming addrRecordTTL across the mesh.
//
// Without it, addresses only ever refresh on connect. An always-on node sits
// on one long-lived connection and emits no new EvtLocalAddressesUpdated, so
// its record keeps the same seq forever and no fresher copy is ever gossiped;
// 48h later its addresses expire everywhere and it can no longer be dialed,
// even though it is still connected and visible in the graph.
//
// The push is deliberately one hop: a receiver refreshes its own TTL but sees
// an equal-seq record as "not news" and does not relay it onward, so this
// costs one small message per connected member per interval and cannot
// cascade.
func (s *EventSync) republishRecords() {
	t := time.NewTicker(recordRepublishInterval)
	done := make(chan struct{})
	s.stop = append(s.stop, func() { close(done); t.Stop() })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.pushRecordsExcept(s.knownRecords(), "")
			}
		}
	}()
}

// Close detaches the service from the host.
// SetCircleHooks lends the gossip the circle service's view (see
// CircleHooks). Without them, v2 carries rosters and events but no own
// admissions or revocations — a pure-connectivity node.
func (s *EventSync) SetCircleHooks(h CircleHooks) {
	s.mu.Lock()
	s.hooks = h
	s.mu.Unlock()
}

func (s *EventSync) circleHooks() CircleHooks {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hooks
}

// kick schedules a full exchange with every connected member.
func (s *EventSync) kick() {
	s.mu.Lock()
	if s.kicking {
		s.mu.Unlock()
		return
	}
	s.kicking = true
	s.mu.Unlock()
	time.AfterFunc(kickDelay, func() {
		s.mu.Lock()
		s.kicking = false
		s.mu.Unlock()
		now := time.Now()
		for _, p := range s.h.Network().Peers() {
			if s.store.IsMember(p, now) {
				s.ExchangeAsync(p)
			}
		}
	})
}

func (s *EventSync) Close() {
	s.h.RemoveStreamHandler(SyncProtocolV2ID)
	for _, f := range s.stop {
		f()
	}
}

// watchOwnRecord keeps the freshest self-signed address record and pushes
// updates to connected members. EvtLocalAddressesUpdated is stateful, so
// the initial record arrives immediately.
func (s *EventSync) watchOwnRecord() {
	sub, err := s.h.EventBus().Subscribe(new(libp2pevent.EvtLocalAddressesUpdated))
	if err != nil {
		return
	}
	done := make(chan struct{})
	s.stop = append(s.stop, func() { close(done); sub.Close() })
	go func() {
		for {
			select {
			case <-done:
				return
			case ev, ok := <-sub.Out():
				if !ok {
					return
				}
				e := ev.(libp2pevent.EvtLocalAddressesUpdated)
				if e.SignedPeerRecord == nil {
					continue
				}
				data, err := e.SignedPeerRecord.Marshal()
				if err != nil {
					continue
				}
				s.mu.Lock()
				first := s.ownRec == nil
				s.ownRec = data
				s.mu.Unlock()
				if !first {
					s.pushRecordsExcept([][]byte{data}, "")
				}
			}
		}
	}()
}

// ExchangeAsync runs a full-state exchange with a peer in the background,
// tolerating failure — anti-entropy retries on every future connect.
func (s *EventSync) ExchangeAsync(p peer.ID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
		defer cancel()
		_ = s.exchange(ctx, p, s.log.All(), s.knownRecords(), true)
	}()
}

// PublishStatements pushes freshly learned or signed admissions and
// revocations of one circle to the connected members verified in it — the
// rumor-mill push for the statement set (a `circle admit` or `circle
// revoke` here).
func (s *EventSync) PublishStatements(circleDID string, admissions, revocations [][]byte) {
	if len(admissions) == 0 && len(revocations) == 0 {
		return
	}
	s.publishSets([]circleSet{{DID: circleDID, Admissions: admissions, Revocations: revocations}}, "")
}

// PublishHandover pushes a circle's key handover to the connected members
// of the circle at once: a rotation must not wait for the first statement
// of the new key to reach them, least of all after a compromise.
func (s *EventSync) PublishHandover(circleDID string, handover []byte) {
	s.publishSets([]circleSet{{DID: circleDID, Handovers: [][]byte{handover}}}, "")
}

// publishSets pushes per-circle deltas to the connected members verified
// in each circle, v2 speakers only (an older peer has no roster to put
// them in). Fire-and-forget: the reply is drained, not applied.
func (s *EventSync) publishSets(sets []circleSet, except peer.ID) {
	if len(sets) == 0 {
		return
	}
	now := time.Now()
	for _, p := range s.h.Network().Peers() {
		if p == except || !s.store.IsMember(p, now) {
			continue
		}
		var mine []circleSet
		for _, set := range sets {
			if s.store.In(p, set.DID, now) {
				mine = append(mine, set)
			}
		}
		if len(mine) == 0 {
			continue
		}
		go func(p peer.ID, sets []circleSet) {
			ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
			defer cancel()
			str, err := s.h.NewStream(ctx, p, SyncProtocolV2ID)
			if err != nil {
				return
			}
			defer str.Close()
			if deadline, ok := ctx.Deadline(); ok {
				_ = str.SetDeadline(deadline)
			}
			if writeSyncV2(str, syncPayloadV2{Circles: sets}) == nil {
				_, _ = readSyncV2(str)
			}
		}(p, mine)
	}
}

// setsFor builds the per-circle sets for one peer: a set for every circle
// the peer is a live device of here, with the given events (the
// membership-event log belongs to the first circle, the one it was always
// about) and — for a full exchange — every admission the roster holds, this
// node's own, and the circle's live revocations.
func (s *EventSync) setsFor(p peer.ID, evs []*event.Event, full bool) []circleSet {
	now := time.Now()
	hooks := s.circleHooks()
	var out []circleSet
	for i, r := range s.store.Rosters() {
		did := r.CircleDID()
		if !s.store.In(p, did, now) {
			continue
		}
		set := circleSet{DID: did, Roots: []string{did}}
		if i == 0 {
			set.Events = evs
		}
		if full {
			for _, h := range r.Roots().Handovers(did) {
				if raw, err := h.Bytes(); err == nil {
					set.Handovers = append(set.Handovers, raw)
				}
			}
			// Every admission the roster keeps for a device, not its
			// entry alone: a restoration held beside a stale renewal is
			// what a peer needs when the removal reaches it later (Codex
			// review, 2026-11-06).
			for _, dev := range r.Devices() {
				for _, d := range r.Held(dev.DID) {
					if raw, err := d.Stmt.Bytes(); err == nil {
						set.Admissions = append(set.Admissions, raw)
					}
				}
			}
			if hooks.OwnAdmissions != nil {
				set.Admissions = append(set.Admissions, hooks.OwnAdmissions(did)...)
			}
			if hooks.Revocations != nil {
				set.Revocations = hooks.Revocations(did)
			}
		}
		if full || len(set.Events) > 0 {
			out = append(out, set)
		}
	}
	return out
}

// Publish sends events to every connected member — the rumor-mill push for
// locally created events (approve/revoke on the master). The events must
// already be in the log.
func (s *EventSync) Publish(evs []*event.Event) {
	s.publishExcept(evs, "")
}

func (s *EventSync) publishExcept(evs []*event.Event, except peer.ID) {
	if len(evs) == 0 {
		return
	}
	now := time.Now()
	for _, p := range s.h.Network().Peers() {
		if p == except || !s.store.IsMember(p, now) {
			continue
		}
		go func(p peer.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
			defer cancel()
			_ = s.exchange(ctx, p, evs, nil, false)
		}(p)
	}
}

// pushRecordsExcept sends address records to connected members. Fire-and-forget: the
// responder's reply is drained but NOT re-applied — pushes must never
// trigger further pushes, or the mesh feeds itself forever (anti-entropy
// on connect covers whatever a drained reply might have carried).
func (s *EventSync) pushRecordsExcept(recs [][]byte, except peer.ID) {
	if len(recs) == 0 {
		return
	}
	now := time.Now()
	subjects := make([]peer.ID, len(recs))
	for i, data := range recs {
		subjects[i], _ = recordSubject(data)
	}
	for _, p := range s.h.Network().Peers() {
		if p == except || !s.store.IsMember(p, now) {
			continue
		}
		// A record goes only to peers that share a circle with its subject.
		var mine [][]byte
		for i, data := range recs {
			if subjects[i] == "" || subjects[i] == s.h.ID() || s.sharesCircle(subjects[i], p) {
				mine = append(mine, data)
			}
		}
		if len(mine) == 0 {
			continue
		}
		go func(p peer.ID, recs [][]byte) {
			ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
			defer cancel()
			str, err := s.h.NewStream(ctx, p, SyncProtocolV2ID)
			if err != nil {
				return
			}
			defer str.Close()
			if deadline, ok := ctx.Deadline(); ok {
				_ = str.SetDeadline(deadline)
			}
			if writeSyncV2(str, syncPayloadV2{Records: recs}) == nil {
				_, _ = readSyncV2(str) // drain so the responder isn't left hanging
			}
		}(p, mine)
	}
}

// exchange sends state to a peer and applies whatever it answers with.
// full says whether the per-circle sets carry the whole roster
// (anti-entropy) or only the given events (a push).
func (s *EventSync) exchange(ctx context.Context, p peer.ID, evs []*event.Event, recs [][]byte, full bool) error {
	str, err := s.h.NewStream(ctx, p, SyncProtocolV2ID)
	if err != nil {
		return err
	}
	defer str.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(deadline)
	}
	if full {
		recs = s.knownRecordsFor(p)
	}
	if err := writeSyncV2(str, syncPayloadV2{Circles: s.setsFor(p, evs, full), Records: recs}); err != nil {
		return err
	}
	theirs, err := readSyncV2(str)
	if err != nil {
		str.Reset()
		return err
	}
	s.applyV2(theirs, p)
	return nil
}

// handleSyncV2 is the responder side of /fabric/sync/2: answer with our
// full per-circle state for the circles we share, then apply theirs.
func (s *EventSync) handleSyncV2(str network.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(exchangeTimeout))
	p := str.Conn().RemotePeer()
	if !s.store.IsMember(p, time.Now()) {
		str.Reset()
		return
	}
	theirs, err := readSyncV2(str)
	if err != nil {
		str.Reset()
		return
	}
	if err := writeSyncV2(str, syncPayloadV2{Circles: s.setsFor(p, s.log.All(), true), Records: s.knownRecordsFor(p)}); err != nil {
		str.Reset()
		return
	}
	s.applyV2(theirs, p)
}

// applyV2 ingests per-circle sets: each into the roster of its circle (a
// set for a circle not held here is dropped unread), events through the
// log as in v1, revocations through the circle hooks. What was genuinely
// new is relayed on — events to every member, admissions and revocations only
// to the members verified in that circle.
func (s *EventSync) applyV2(pl syncPayloadV2, from peer.ID) {
	now := time.Now()
	hooks := s.circleHooks()
	var (
		freshEvents []*event.Event
		deltas      []circleSet
	)
	for _, set := range pl.Circles {
		// The set is keyed by the circle DID; Roots repeats it (a peer on
		// an older binary may list more than one).
		roster, ok := s.store.RosterFor(set.DID)
		for _, did := range set.Roots {
			if ok {
				break
			}
			roster, ok = s.store.RosterFor(did)
		}
		if !ok {
			continue
		}
		delta := circleSet{DID: set.DID, Roots: set.Roots}
		// The key history first: an admission of the new key would teach
		// it too, but a bare handover (a rotation with nothing signed yet)
		// must reach the roster on its own.
		for _, raw := range set.Handovers {
			st, err := statement.Decode(raw)
			if err != nil || st.Payload.Typ != statement.TypeHandover {
				continue
			}
			// Verified before it is pushed: a handover that does not
			// extend the history here — unsigned by the circle's key,
			// conflicting, or old news — is dropped on the spot, never
			// relayed (an invalid one would otherwise circle a mesh for
			// good, since no node records it; Codex review, 2026-11-07).
			grew, err := roster.Roots().Extends(st)
			if err != nil {
				log.Printf("sync: key handover from %s for circle %s refused: %v", from, shortDID(set.DID), err)
				continue
			}
			// Pushed before it applies here: a compromise retires the
			// devices the old key admitted, and they must still hear of
			// it while the view counts them (Codex review, 2026-11-06).
			if grew {
				s.publishSets([]circleSet{{DID: set.DID, Handovers: [][]byte{raw}}}, from)
			}
			// A known handover still goes to the table: a history whose
			// save failed is written on the retry (Codex review,
			// 2026-11-07).
			if _, err := s.store.AddHandover(set.DID, st); err != nil {
				log.Printf("sync: key handover from %s for circle %s: %v", from, shortDID(set.DID), err)
			}
		}
		event.Sort(set.Events)
		for _, e := range set.Events {
			if !roster.Honours(e.Payload.Ns) {
				continue
			}
			isNew, err := s.log.Add(e, now)
			if err != nil || !isNew {
				continue
			}
			freshEvents = append(freshEvents, e)
			if s.onApply != nil {
				s.onApply(e)
			}
		}
		for _, raw := range set.Admissions {
			st, err := statement.Decode(raw)
			if err != nil {
				continue
			}
			if fresh, err := s.store.AddAdmission(st, now); err == nil && fresh {
				delta.Admissions = append(delta.Admissions, raw)
			}
		}
		if hooks.Ingest != nil && len(set.Revocations) > 0 {
			fresh, err := hooks.Ingest(from, set.Revocations)
			if err != nil {
				log.Printf("sync: revocations from %s for circle %s: %v", from, set.DID, err)
			}
			delta.Revocations = fresh
		}
		if len(delta.Admissions) > 0 || len(delta.Revocations) > 0 || len(delta.Handovers) > 0 {
			deltas = append(deltas, delta)
		}
	}
	s.publishExcept(freshEvents, from)
	s.publishSets(deltas, from)

	var freshRecords [][]byte
	for _, data := range pl.Records {
		if s.consumeRecord(data, now) {
			freshRecords = append(freshRecords, data)
		}
	}
	s.pushRecordsExcept(freshRecords, from)
}

// consumeRecord verifies and stores one gossiped address record, reporting
// whether it was genuinely NEW. Only current members' records are kept —
// the envelope signature proves the device said it, membership decides
// whether we care. Freshness is tracked here with a strictly-greater seq
// check: the peerstore's ConsumePeerRecord accepts equal-seq records as
// true, and treating those as fresh once caused an infinite re-push storm
// between nodes.
func (s *EventSync) consumeRecord(data []byte, now time.Time) bool {
	if s.cab == nil {
		return false
	}
	env, untyped, err := record.ConsumeEnvelope(data, peer.PeerRecordEnvelopeDomain)
	if err != nil {
		return false
	}
	rec, ok := untyped.(*peer.PeerRecord)
	if !ok || rec.PeerID == s.h.ID() || !s.store.IsMember(rec.PeerID, now) {
		return false
	}
	// Keep the high-water mark even after the address TTL expires. An equal
	// version may refresh its TTL, but an older version must never resurrect
	// endpoints withdrawn by the device.
	s.mu.Lock()
	if rec.Seq < s.lastSeq[rec.PeerID] {
		s.mu.Unlock()
		return false
	}
	previous := s.cab.GetPeerRecord(rec.PeerID)
	accepted, err := s.cab.ConsumePeerRecord(env, addrRecordTTL)
	if err != nil || !accepted {
		s.mu.Unlock()
		return false
	}
	if previous != nil {
		if old, err := previous.Record(); err == nil {
			if oldRec, ok := old.(*peer.PeerRecord); ok && oldRec.Seq < rec.Seq {
				// ConsumePeerRecord adds addresses; it does not remove those the
				// owner withdrew. Remove only addresses from the superseded record.
				for _, addr := range oldRec.Addrs {
					retained := false
					for _, current := range rec.Addrs {
						if addr.Equal(current) {
							retained = true
							break
						}
					}
					if !retained {
						s.h.Peerstore().SetAddr(rec.PeerID, addr, 0)
					}
				}
			}
		}
	}
	if rec.Seq <= s.lastSeq[rec.PeerID] {
		s.mu.Unlock()
		return false
	}
	s.lastSeq[rec.PeerID] = rec.Seq
	onRecord := s.onRecord
	s.mu.Unlock()
	if onRecord != nil {
		onRecord(rec.PeerID, rec.Seq)
	}
	return true
}

// SetOnRecord installs a callback for strictly newer, verified member address
// records. It runs outside the sync lock; callers should return promptly.
func (s *EventSync) SetOnRecord(f func(peer.ID, uint64)) {
	s.mu.Lock()
	s.onRecord = f
	s.mu.Unlock()
}

// SeedRecords replays persisted address records into the address book —
// the restart warm-up. Consumption verifies each envelope and checks
// membership as usual; nothing is pushed (peers get records through the
// normal anti-entropy on connect).
func (s *EventSync) SeedRecords(recs [][]byte) {
	now := time.Now()
	n := 0
	for _, data := range recs {
		if s.consumeRecord(data, now) {
			n++
		}
	}
	log.Printf("address cache: %d member record(s) restored", n)
}

// KnownRecords returns this node's own signed address record plus the
// freshest record held for every current member — the set worth
// persisting across a restart.
func (s *EventSync) KnownRecords() [][]byte { return s.knownRecords() }

// knownRecords returns our own signed address record plus the freshest
// record we hold for every current member (what is worth persisting).
func (s *EventSync) knownRecords() [][]byte { return s.recordsFor(nil) }

// knownRecordsFor is knownRecords narrowed to what one peer may learn:
// our own record and the records of members that share a circle with it.
// Where a device lives is its circle's business (Codex review, 2026-11-04).
func (s *EventSync) knownRecordsFor(p peer.ID) [][]byte { return s.recordsFor(&p) }

func (s *EventSync) recordsFor(to *peer.ID) [][]byte {
	var out [][]byte
	s.mu.Lock()
	if s.ownRec != nil {
		out = append(out, s.ownRec)
	}
	s.mu.Unlock()
	if s.cab == nil {
		return out
	}
	members, _ := s.store.Snapshot()
	for p := range members {
		if p == s.h.ID() || (to != nil && !s.sharesCircle(p, *to)) {
			continue
		}
		if env := s.cab.GetPeerRecord(p); env != nil {
			if data, err := env.Marshal(); err == nil {
				out = append(out, data)
			}
		}
	}
	return out
}

// sharesCircle reports whether two members are live devices of a common
// circle held here.
func (s *EventSync) sharesCircle(a, b peer.ID) bool {
	if a == b {
		return true
	}
	now := time.Now()
	in := s.store.Circles(b, now)
	for _, c := range s.store.Circles(a, now) {
		for _, d := range in {
			if c == d {
				return true
			}
		}
	}
	return false
}

// recordSubject is the peer a signed address record is about.
func recordSubject(data []byte) (peer.ID, bool) {
	_, untyped, err := record.ConsumeEnvelope(data, peer.PeerRecordEnvelopeDomain)
	if err != nil {
		return "", false
	}
	rec, ok := untyped.(*peer.PeerRecord)
	if !ok {
		return "", false
	}
	return rec.PeerID, true
}

func writeSyncV2(str network.Stream, pl syncPayloadV2) error {
	data, err := cbor.Marshal(pl)
	if err != nil {
		return err
	}
	return wire.WriteFrame(str, data)
}

func readSyncV2(str network.Stream) (syncPayloadV2, error) {
	data, err := wire.ReadFrame(str, maxEventsWireSize)
	if err != nil {
		return syncPayloadV2{}, fmt.Errorf("reading sync payload: %w", err)
	}
	var pl syncPayloadV2
	if err := cbor.Unmarshal(data, &pl); err != nil {
		return syncPayloadV2{}, fmt.Errorf("decoding sync payload: %w", err)
	}
	return pl, nil
}
