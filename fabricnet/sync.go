package fabricnet

import (
	"context"
	"fmt"
	"time"

	"aethera.dev/fabric/event"
	"aethera.dev/fabric/internal/wire"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// EventsProtocolID carries membership-event gossip (spec §5). Two motions on
// one protocol: anti-entropy — after every successful membership handshake
// (and on reconnect between known members) the peers swap full event logs —
// and rumor mill: newly learned events are pushed on to other connected
// members, which makes revocation cut-off real-time rather than
// next-connect. Members only; strangers are reset.
const EventsProtocolID = "/fabric/events/1"

// A log entry is a few hundred bytes; even a large mesh with a deep
// revocation history stays far under this.
const maxEventsWireSize = 1 << 20

const exchangeTimeout = 15 * time.Second

// EventApplied is invoked once per newly learned event, in apply order,
// after it entered the log. The daemon uses it to update the member store,
// persist the log, and surface the spec-§5 notifications.
type EventApplied func(e *event.Event)

// EventSync gossips membership events between members.
type EventSync struct {
	h       host.Host
	log     *event.Log
	store   *MemberStore
	onApply EventApplied
	stop    func()
}

// NewEventSync wires the gossip protocol onto the host. onApply may be nil.
// Call (*AuthService).SetOnAuthenticated with s.ExchangeAsync to complete the
// anti-entropy wiring — freshly authenticated peers exchange logs; already-
// known members exchange on reconnect via the Connected notification here.
func NewEventSync(h host.Host, log *event.Log, store *MemberStore, onApply EventApplied) *EventSync {
	s := &EventSync{h: h, log: log, store: store, onApply: onApply}
	h.SetStreamHandler(EventsProtocolID, s.handle)
	nb := &network.NotifyBundle{ConnectedF: func(_ network.Network, c network.Conn) {
		p := c.RemotePeer()
		if s.store.IsMember(p, time.Now()) {
			s.ExchangeAsync(p)
		}
	}}
	h.Network().Notify(nb)
	s.stop = func() { h.Network().StopNotify(nb) }
	return s
}

// Close detaches the service from the host.
func (s *EventSync) Close() {
	s.h.RemoveStreamHandler(EventsProtocolID)
	s.stop()
}

// ExchangeAsync runs a full-log exchange with a peer in the background,
// tolerating failure — anti-entropy retries on every future connect.
func (s *EventSync) ExchangeAsync(p peer.ID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
		defer cancel()
		_ = s.exchange(ctx, p, s.log.All())
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
			_ = s.exchange(ctx, p, evs)
		}(p)
	}
}

// exchange sends events to a peer and applies whatever it answers with.
func (s *EventSync) exchange(ctx context.Context, p peer.ID, evs []*event.Event) error {
	str, err := s.h.NewStream(ctx, p, EventsProtocolID)
	if err != nil {
		return err
	}
	defer str.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(deadline)
	}
	if err := writeEvents(str, evs); err != nil {
		return err
	}
	theirs, err := readEvents(str)
	if err != nil {
		str.Reset()
		return err
	}
	s.applyBatch(theirs, p)
	return nil
}

// handle is the responder side: apply theirs, answer with our full log.
func (s *EventSync) handle(str network.Stream) {
	defer str.Close()
	_ = str.SetDeadline(time.Now().Add(exchangeTimeout))
	p := str.Conn().RemotePeer()
	if !s.store.IsMember(p, time.Now()) {
		str.Reset()
		return
	}
	theirs, err := readEvents(str)
	if err != nil {
		str.Reset()
		return
	}
	if err := writeEvents(str, s.log.All()); err != nil {
		str.Reset()
		return
	}
	s.applyBatch(theirs, p)
}

// applyBatch adds a batch to the log and relays what was genuinely new to
// the other connected members. Dedup in the log terminates the relay.
func (s *EventSync) applyBatch(evs []*event.Event, from peer.ID) {
	now := time.Now()
	event.Sort(evs)
	var fresh []*event.Event
	for _, e := range evs {
		isNew, err := s.log.Add(e, now)
		if err != nil || !isNew {
			continue // invalid or stale events are dropped, duplicates ignored
		}
		fresh = append(fresh, e)
		if s.onApply != nil {
			s.onApply(e)
		}
	}
	s.publishExcept(fresh, from)
}

func writeEvents(str network.Stream, evs []*event.Event) error {
	data, err := cbor.Marshal(evs)
	if err != nil {
		return err
	}
	return wire.WriteFrame(str, data)
}

func readEvents(str network.Stream) ([]*event.Event, error) {
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
