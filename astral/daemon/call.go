package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/astral"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/statement"
)

// Request/reply over the plane (astral/call.go has the journal side). The
// reply to a request lives with the request, on the host that journaled
// it, so every verb here routes like an ack does: to the journal that
// holds that one event.
//
//	caller                 host of the request            worker
//	AppendRequest  ──────▶ event + call record
//	                       claim  ◀────────────────────── Claim
//	                       reply recorded, request acked ◀ Complete (signed)
//	Outcome        ──────▶ the reply (parks until it is there)
//	  checks the signature and the signer's right to answer
//	ReleaseCall    ──────▶ call record gone, quota freed

// ErrUnverified is a reply the caller's own node would not accept: its
// signature does not bind it to the request, or the signer was not
// entitled to answer. The host that handed it over is not believed.
var ErrUnverified = errors.New("astral: reply failed the caller's check")

// anyCall is the one key parked outcome waits share: every change to a
// call wakes them all and each re-reads its own record. Waits on replies
// are few; a key per request would need reaping.
var anyCall = astral.Ref{}

func (d *Daemon) callsChanged() { d.calls.notify(anyCall) }

// outcomeTimeout bounds how long one outcome request may park.
func outcomeTimeout(asked time.Duration) time.Duration {
	return min(max(asked, 0), 10*time.Minute)
}

// isErr reports whether err is the sentinel, as returned by this node's
// store or as the text of a remote host's refusal (the wire carries
// refusals as strings).
func isErr(err, sentinel error) bool {
	return err != nil && (errors.Is(err, sentinel) || strings.Contains(err.Error(), sentinel.Error()))
}

// notHere reports whether a host's answer means "I do not have that event
// (or its call)" rather than a refusal or an outage. Only this answer lets
// host discovery move on and rule the host out; a host that could not be
// asked is not ruled out.
func notHere(err error) bool {
	return isErr(err, astral.ErrNoEvent) || isErr(err, astral.ErrNoCall) || notHosted(err)
}

// notHosted is a host that does not have the name at all (a stale
// announcement, or it expired there).
func notHosted(err error) bool {
	return isErr(err, astral.ErrUnknownSubject) || isErr(err, astral.ErrSubjectExpired)
}

// onEventHost runs try against the journal that holds one event of ref:
// this node's (host "") when the subject is hosted here, its one remote
// host, or for a spread name the host the event was claimed from or
// published to. When that is not known (this daemon restarted in between,
// or the entry aged out) each host is tried and the one that has the event
// answers.
//
// try must fail with an error notHere recognises when the journal it asked
// does not hold the event: success ends the search, so "nothing to do
// here" must never be reported as success (Codex review, 2026-11-16). When
// no host succeeds, a host that refused or could not be asked decides the
// error, since it may be the one that has the event; only when every host
// answered "not here" is that the result.
func (d *Daemon) onEventHost(ref astral.Ref, eventID string, try func(host string) error) error {
	m, local, err := d.Store.Subject(ref)
	if err != nil {
		return err
	}
	if local && !m.Spread {
		return try("")
	}
	if !local {
		host, ok, err := d.Store.Host(ref)
		if err != nil {
			return err
		}
		if ok {
			return try(host)
		}
	}
	if origin, ok := d.origins.get(ref, eventID); ok && (origin != "" || local) {
		return try(origin)
	}
	hosts, err := d.Store.SpreadHosts(ref)
	if err != nil {
		return err
	}
	sources := make([]string, 0, len(hosts)+1)
	if local {
		sources = append(sources, "")
	}
	for _, h := range hosts {
		sources = append(sources, h.Host)
	}
	var failed, absent error
	for _, host := range sources {
		err := try(host)
		switch {
		case err == nil:
			d.origins.put(ref, eventID, host)
			return nil
		case !notHere(err):
			if failed == nil {
				failed = err
			}
		case absent == nil || notHosted(absent):
			// "No such event" says more than "no such subject".
			absent = err
		}
	}
	switch {
	case failed != nil:
		return failed
	case absent != nil:
		return absent
	}
	return astral.ErrUnknownSubject
}

// Complete finishes a request this principal holds the lease on: the host
// records reply as the request's outcome and acknowledges the request in
// one write. The reply is signed — by the sub-key on the client side, by
// the device key here. delivered is false when no caller is waiting for
// the reply (none was wanted, or the caller is gone); the request is
// acknowledged either way, so Complete is how a worker finishes any
// request.
func (d *Daemon) Complete(pr *astral.Principal, ref astral.Ref, requestID string, reply astral.Event) (delivered bool, err error) {
	if reply.CorrelationID == "" {
		reply.CorrelationID = requestID
	}
	reply.Source = stampSource(reply.Source, d.principalLabel(pr))
	if reply.At == 0 {
		reply.At = time.Now().UnixNano()
	}
	if pr == nil && len(reply.Signature) == 0 && d.Fabric != nil {
		dg := astral.ReplyDigest(ref, reply)
		sig, signer, err := d.Fabric.DeviceSign(dg[:])
		if err != nil {
			return false, err
		}
		reply.Signer, reply.Signature = signer, sig
	}
	err = d.onEventHost(ref, requestID, func(host string) error {
		if host == "" {
			if err := d.localAuthorizeHeld(pr, OpComplete, ref, requestID, replyDigestValue(reply)); err != nil {
				return err
			}
			var err error
			delivered, err = d.completeLocal(ref, requestID, d.localPrincipal(pr), reply)
			return err
		}
		resp, err := d.remote(host, request{Op: OpComplete, Circle: ref.Circle, Name: ref.Name, EventID: requestID, Event: reply, Principal: pr})
		delivered = resp.Delivered
		return err
	})
	if err == nil {
		d.origins.drop(ref, requestID)
	}
	return delivered, err
}

// completeLocal is the host's side of Complete: the reply answers this
// request and is signed by the principal that holds its live lease (the
// store checks the lease in the same write that records the reply). A solo
// node has no keys and no peers; there the lease alone decides.
func (d *Daemon) completeLocal(ref astral.Ref, requestID, principal string, reply astral.Event) (bool, error) {
	if reply.Kind == "" {
		return false, errors.New("astral: reply kind required")
	}
	if reply.CorrelationID != requestID {
		return false, fmt.Errorf("%w: reply does not answer request %s", ErrDenied, requestID)
	}
	if d.Fabric != nil {
		if err := astral.VerifyReply(ref, reply); err != nil {
			return false, fmt.Errorf("%w: %v", ErrDenied, err)
		}
		if reply.Signer != principal {
			return false, fmt.Errorf("%w: reply signed by %s, handed in by %s", ErrDenied, keyLabel(reply.Signer), keyLabel(principal))
		}
	}
	if reply.At == 0 {
		reply.At = time.Now().UnixNano()
	}
	if reply.ID == "" {
		reply.ID = requestID + ":reply"
	}
	delivered, err := d.Store.Complete(ref, requestID, principal, reply, time.Now())
	if err != nil {
		return false, err
	}
	d.callsChanged()
	return delivered, nil
}

// Outcome returns the reply to a request this principal published,
// waiting up to timeout for it; nil when there is none yet. The reply is
// checked here before it is handed on, whichever journal it came from:
// this node's own is no exception, because the check is also what refuses
// the reply of a worker whose key has been revoked since it answered.
// Reading does not consume: ReleaseCall does, once the caller has acted on
// the reply.
func (d *Daemon) Outcome(ctx context.Context, pr *astral.Principal, ref astral.Ref, requestID string, timeout time.Duration) (*astral.Event, error) {
	timeout = outcomeTimeout(timeout)
	var reply *astral.Event
	err := d.onEventHost(ref, requestID, func(host string) error {
		if host == "" {
			if err := d.localAuthorizeHeld(pr, OpOutcome, ref, requestID, ""); err != nil {
				return err
			}
			caller := d.localPrincipal(pr)
			call, err := d.awaitOutcome(ctx, ref, requestID, caller, timeout, holdOf("", caller, pr))
			if err != nil || call == nil {
				return err
			}
			if err := d.verifyOutcome(ctx, ref, requestID, *call.Outcome, call.Chain); err != nil {
				return fmt.Errorf("%w (kept on this node): %v", ErrUnverified, err)
			}
			reply = call.Outcome
			return nil
		}
		resp, err := d.remoteCtx(ctx, host, request{Op: OpOutcome, Circle: ref.Circle, Name: ref.Name, EventID: requestID, LeaseNS: int64(timeout), Principal: pr}, timeout+5*time.Second)
		if err != nil || resp.Outcome == nil {
			return err
		}
		if err := d.verifyOutcome(ctx, ref, requestID, *resp.Outcome, resp.Chain); err != nil {
			return fmt.Errorf("%w (from %s): %v", ErrUnverified, d.hostLabel(host), err)
		}
		reply = resp.Outcome
		return nil
	})
	return reply, err
}

// ReleaseCall tells the host the caller has its reply (or no longer wants
// one): the call record goes and its place in the quota is free. A call no
// host holds any more (released before, or swept) counts as released; a
// host that says "not here" is only that, and the search goes on to the
// host that has it.
func (d *Daemon) ReleaseCall(pr *astral.Principal, ref astral.Ref, requestID string) error {
	err := d.onEventHost(ref, requestID, func(host string) error {
		if host == "" {
			if err := d.localAuthorizeHeld(pr, OpRelease, ref, requestID, ""); err != nil {
				return err
			}
			if err := d.Store.ReleaseCall(ref, requestID, d.localPrincipal(pr)); err != nil {
				return err
			}
			d.callsChanged()
			return nil
		}
		_, err := d.remote(host, request{Op: OpRelease, Circle: ref.Circle, Name: ref.Name, EventID: requestID, Principal: pr})
		return err
	})
	if isErr(err, astral.ErrNoCall) {
		err = nil
	}
	if err == nil {
		d.origins.drop(ref, requestID)
	}
	return err
}

// awaitOutcome parks until the call is done or timeout. It returns the
// call once it has a reply, nil at the timeout, and ErrNoReply when the
// request was acknowledged without one. Each look at the record tells the
// sweep the caller is still here, so the wait re-reads on a timer too.
func (d *Daemon) awaitOutcome(ctx context.Context, ref astral.Ref, requestID, caller string, timeout time.Duration, hold astral.Hold) (*astral.Call, error) {
	ctx, done := d.park(ctx, ref, hold, "")
	defer done()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	seen := time.NewTicker(max(astral.CallIdleTTL/4, 50*time.Millisecond))
	defer seen.Stop()
	for {
		// Take the generation before reading, so a completion between the
		// read and the park cannot be missed.
		changed := d.calls.chanFor(anyCall)
		call, err := d.Store.Outcome(ref, requestID, caller, time.Now())
		if err != nil {
			return nil, err
		}
		if call.Outcome != nil {
			return &call, nil
		}
		if call.Closed {
			return nil, fmt.Errorf("%w (%s)", astral.ErrNoReply, requestID)
		}
		select {
		case <-changed:
		case <-seen.C:
		case <-deadline.C:
			return nil, nil
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), errRevoked) {
				return nil, errRevoked
			}
			return nil, ctx.Err()
		}
	}
}

// verifyOutcome is the caller's own check of a reply before its application
// sees it (memo §12.3): the signature binds the reply to this request, and
// the signer is entitled to answer it — it holds `claim` on the subject, by
// the chain the host kept from its lease or, for a device with no chain on
// record, by its admission in the circle. A host can drop a reply; it
// cannot make one up or pass off another request's.
func (d *Daemon) verifyOutcome(ctx context.Context, ref astral.Ref, requestID string, reply astral.Event, chain []byte) error {
	if reply.CorrelationID != requestID {
		return fmt.Errorf("it answers request %q", reply.CorrelationID)
	}
	if d.Fabric == nil {
		return nil
	}
	if err := astral.VerifyReply(ref, reply); err != nil {
		return err
	}
	if reply.Signer == d.selfDID() {
		return nil
	}
	if d.Fabric.Circle == nil {
		return errors.New("no circle service on this node to check the signer against")
	}
	want := statement.Want{
		Sub: ref.Circle, Res: statement.Resource{Kind: statement.KindSubject, Name: ref.Name},
		Verb: statement.VerbClaim, Now: time.Now(),
	}
	if len(chain) > 0 {
		if err := d.Fabric.Circle.CheckChainOf(chain, reply.Signer, want); err != nil {
			return fmt.Errorf("signer %s: %w", keyLabel(reply.Signer), err)
		}
		return nil
	}
	p, err := peerOfDID(reply.Signer)
	if err != nil {
		return fmt.Errorf("signer %s: %w", keyLabel(reply.Signer), err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.Fabric.Circle.Verify(ctx, p, want); err != nil {
		return fmt.Errorf("signer %s: %w", keyLabel(reply.Signer), err)
	}
	return nil
}

// peerOfDID is the peer ID of a device key (the inverse of deviceDIDOf).
func peerOfDID(key string) (peer.ID, error) {
	pub, err := did.KeyFor(key)
	if err != nil {
		return "", err
	}
	pk, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pk)
}
