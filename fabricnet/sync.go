package fabricnet

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aethera.dev/fabric/event"
	"aethera.dev/fabric/internal/wire"

	"github.com/fxamacker/cbor/v2"
	libp2pevent "github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/record"
)

// Gossip protocols (spec §5 + connectivity-model memo). Two motions on one
// channel: anti-entropy — after every successful membership handshake (and
// on reconnect between known members) peers swap full state — and rumor
// mill: newly learned items are pushed on to other connected members.
// Members only; strangers are reset.
//
// SyncProtocolID carries membership events plus signed peer address
// records (the knowledge plane's WHERE, self-attested by each device's
// key). EventsProtocolID is the events-only predecessor, still served so
// a mixed-version mesh keeps its membership gossip during rolling
// upgrades.
const (
	SyncProtocolID   = "/fabric/sync/1"
	EventsProtocolID = "/fabric/events/1"
)

// A log entry or address record is a few hundred bytes; even a large mesh
// with a deep history stays far under this.
const maxEventsWireSize = 1 << 20

const exchangeTimeout = 15 * time.Second

// addrRecordTTL bounds how long gossiped addresses are kept without being
// refreshed; anti-entropy on every connect refreshes them in practice.
const addrRecordTTL = 48 * time.Hour

// syncPayload is one direction of a /fabric/sync/1 exchange.
type syncPayload struct {
	Events  []*event.Event `cbor:"events,omitempty"`
	Records [][]byte       `cbor:"records,omitempty"` // marshaled signed peer-record envelopes
}

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

	mu      sync.Mutex
	ownRec  []byte             // this host's latest signed peer record
	lastSeq map[peer.ID]uint64 // highest record seq accepted per peer

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
	h.SetStreamHandler(SyncProtocolID, s.handleSync)
	h.SetStreamHandler(EventsProtocolID, s.handleV1)
	nb := &network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
		p := c.RemotePeer()
		if s.store.IsMember(p, time.Now()) {
			s.ExchangeAsync(p)
		}
	}}
	h.Network().Notify(nb)
	s.stop = append(s.stop, func() { h.Network().StopNotify(nb) })
	s.watchOwnRecord()
	return s
}

// Close detaches the service from the host.
func (s *EventSync) Close() {
	s.h.RemoveStreamHandler(SyncProtocolID)
	s.h.RemoveStreamHandler(EventsProtocolID)
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
		_ = s.exchange(ctx, p, s.log.All(), s.knownRecords())
	}()
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
			_ = s.exchange(ctx, p, evs, nil)
		}(p)
	}
}

// pushRecordsExcept sends address records to connected members (sync/1
// speakers only — v1 peers have no record support). Fire-and-forget: the
// responder's reply is drained but NOT re-applied — pushes must never
// trigger further pushes, or the mesh feeds itself forever (anti-entropy
// on connect covers whatever a drained reply might have carried).
func (s *EventSync) pushRecordsExcept(recs [][]byte, except peer.ID) {
	if len(recs) == 0 {
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
			str, err := s.h.NewStream(ctx, p, SyncProtocolID)
			if err != nil {
				return
			}
			defer str.Close()
			if deadline, ok := ctx.Deadline(); ok {
				_ = str.SetDeadline(deadline)
			}
			if writeSync(str, syncPayload{Records: recs}) == nil {
				_, _ = readSync(str) // drain so the responder isn't left hanging
			}
		}(p)
	}
}

// exchange sends state to a peer and applies whatever it answers with.
// sync/1 is preferred; events/1 keeps membership gossip alive with
// older nodes.
func (s *EventSync) exchange(ctx context.Context, p peer.ID, evs []*event.Event, recs [][]byte) error {
	str, err := s.h.NewStream(ctx, p, SyncProtocolID, EventsProtocolID)
	if err != nil {
		return err
	}
	defer str.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(deadline)
	}
	if str.Protocol() == EventsProtocolID {
		if err := writeEventsV1(str, evs); err != nil {
			return err
		}
		theirs, err := readEventsV1(str)
		if err != nil {
			str.Reset()
			return err
		}
		s.applyPayload(syncPayload{Events: theirs}, p)
		return nil
	}
	if err := writeSync(str, syncPayload{Events: evs, Records: recs}); err != nil {
		return err
	}
	theirs, err := readSync(str)
	if err != nil {
		str.Reset()
		return err
	}
	s.applyPayload(theirs, p)
	return nil
}

// handleSync is the responder side of /fabric/sync/1: apply theirs, answer
// with our full state.
func (s *EventSync) handleSync(str network.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(exchangeTimeout))
	p := str.Conn().RemotePeer()
	if !s.store.IsMember(p, time.Now()) {
		str.Reset()
		return
	}
	theirs, err := readSync(str)
	if err != nil {
		str.Reset()
		return
	}
	if err := writeSync(str, syncPayload{Events: s.log.All(), Records: s.knownRecords()}); err != nil {
		str.Reset()
		return
	}
	s.applyPayload(theirs, p)
}

// handleV1 is the responder side of the events-only predecessor.
func (s *EventSync) handleV1(str network.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(exchangeTimeout))
	p := str.Conn().RemotePeer()
	if !s.store.IsMember(p, time.Now()) {
		str.Reset()
		return
	}
	theirs, err := readEventsV1(str)
	if err != nil {
		str.Reset()
		return
	}
	if err := writeEventsV1(str, s.log.All()); err != nil {
		str.Reset()
		return
	}
	s.applyPayload(syncPayload{Events: theirs}, p)
}

// applyPayload adds a batch to the log and address book, relaying what was
// genuinely new to the other connected members. Dedup (event IDs, record
// seq numbers) terminates the relay.
func (s *EventSync) applyPayload(pl syncPayload, from peer.ID) {
	now := time.Now()
	event.Sort(pl.Events)
	var freshEvents []*event.Event
	for _, e := range pl.Events {
		isNew, err := s.log.Add(e, now)
		if err != nil || !isNew {
			continue // invalid or stale events are dropped, duplicates ignored
		}
		freshEvents = append(freshEvents, e)
		if s.onApply != nil {
			s.onApply(e)
		}
	}
	s.publishExcept(freshEvents, from)

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
	s.mu.Lock()
	stale := rec.Seq <= s.lastSeq[rec.PeerID]
	s.mu.Unlock()
	if stale {
		return false
	}
	accepted, err := s.cab.ConsumePeerRecord(env, addrRecordTTL)
	if err != nil || !accepted {
		return false
	}
	s.mu.Lock()
	if rec.Seq > s.lastSeq[rec.PeerID] {
		s.lastSeq[rec.PeerID] = rec.Seq
	}
	s.mu.Unlock()
	return true
}

// knownRecords returns our own signed address record plus the freshest
// record we hold for every current member.
func (s *EventSync) knownRecords() [][]byte {
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
		if p == s.h.ID() {
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

func writeSync(str network.Stream, pl syncPayload) error {
	data, err := cbor.Marshal(pl)
	if err != nil {
		return err
	}
	return wire.WriteFrame(str, data)
}

func readSync(str network.Stream) (syncPayload, error) {
	data, err := wire.ReadFrame(str, maxEventsWireSize)
	if err != nil {
		return syncPayload{}, fmt.Errorf("reading sync payload: %w", err)
	}
	var pl syncPayload
	if err := cbor.Unmarshal(data, &pl); err != nil {
		return syncPayload{}, fmt.Errorf("decoding sync payload: %w", err)
	}
	return pl, nil
}

func writeEventsV1(str network.Stream, evs []*event.Event) error {
	data, err := cbor.Marshal(evs)
	if err != nil {
		return err
	}
	return wire.WriteFrame(str, data)
}

func readEventsV1(str network.Stream) ([]*event.Event, error) {
	data, err := wire.ReadFrame(str, maxEventsWireSize)
	if err != nil {
		return nil, fmt.Errorf("reading events: %w", err)
	}
	var evs []*event.Event
	if err := cbor.Unmarshal(data, &evs); err != nil {
		return nil, fmt.Errorf("decoding events: %w", err)
	}
	return evs, nil
}
