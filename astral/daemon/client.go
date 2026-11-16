package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ioa.rocks/fabric/astral"
)

// Client is a plane client over a running subsystem's control socket.
// Circle selects which circle names refer to; "" is the node's home circle.
// Signer, when set, makes every call act as that sub-key: the client signs
// the operation and the daemon (and the remote host) check the key's chain
// instead of the device's own admission.
type Client struct {
	Circle string
	Signer *astral.Signer
	http   http.Client
}

// WithKey returns a client acting as the sub-key in a key file; the key's
// circle becomes the client's.
func (c *Client) WithKey(s *astral.Signer) *Client {
	cc := *c
	cc.Signer = s
	cc.Circle = s.Circle
	return &cc
}

// sign builds the envelope for one call, or nil for the device itself.
func (c *Client) sign(op Op, name, eventID, consumer, value string) *astral.Principal {
	if c.Signer == nil {
		return nil
	}
	return c.Signer.Sign(string(op), astral.Ref{Circle: c.Circle, Name: name}, eventID, consumer, value, time.Now())
}

// NewClient builds a client for a state dir's control socket. The default
// directory resolves to the legacy one until the daemon has migrated it.
func NewClient(statePath string) *Client {
	sock := SocketPath(ExistingPath(statePath))
	return &Client{http: http.Client{
		// Waits long-poll; the per-call timeout rides the request body.
		Timeout: 15 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}}
}

// In returns a client addressing circle.
func (c *Client) In(circle string) *Client {
	cc := *c
	cc.Circle = circle
	return &cc
}

func decodeErr(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return errors.New(strings.TrimSpace(string(msg)))
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get("http://astral" + path)
	if err != nil {
		return fmt.Errorf("is `fabric up` running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeErr(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post("http://astral"+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("is `fabric up` running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeErr(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Status reports the subsystem's view.
func (c *Client) Status() (*StatusReply, error) {
	var s StatusReply
	if err := c.get("/v0/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Declare hosts a subject here with explicit delivery policy; an empty
// delivery defaults to exclusive.
func (c *Client) Declare(name string, delivery astral.Delivery, accepts []string) error {
	return c.post("/v0/subjects", declareBody{Circle: c.Circle, Name: name, Delivery: delivery, Accepts: accepts}, nil)
}

// DeclareExpiring is Declare with an explicit lifecycle: idle self-destruct
// TTL and a total-append cap (zero keeps each unlimited).
func (c *Client) DeclareExpiring(name string, delivery astral.Delivery, accepts []string, idle time.Duration, maxEvents int) error {
	return c.post("/v0/subjects", declareBody{
		Circle: c.Circle, Name: name, Delivery: delivery, Accepts: accepts,
		IdleS: int(idle / time.Second), MaxEv: maxEvents,
	}, nil)
}

// DeclareSpread hosts a shared subject here that other nodes may host too
// (spread placement): publishers pick one host and fall over to the next,
// consumers claim from all. Declare it on every node that should host it.
func (c *Client) DeclareSpread(name string, accepts []string) error {
	on := true
	return c.post("/v0/subjects", declareBody{Circle: c.Circle, Name: name, Delivery: astral.DeliveryShared, Accepts: accepts, Spread: &on}, nil)
}

// SetSpread turns spread placement on or off for a subject hosted here,
// leaving the rest of its declaration alone.
func (c *Client) SetSpread(name string, delivery astral.Delivery, accepts []string, on bool) error {
	return c.post("/v0/subjects", declareBody{Circle: c.Circle, Name: name, Delivery: delivery, Accepts: accepts, Spread: &on}, nil)
}

// Drain makes this host of a spread subject refuse new events while it
// keeps serving claims (on=false ends the drain). Remove the subject once
// status shows nothing pending.
func (c *Client) Drain(name string, on bool) error {
	return c.post("/v0/drain", drainBody{Circle: c.Circle, Name: name, Off: !on}, nil)
}

// Remove drops a subject hosted on this node, journal included.
func (c *Client) Remove(name string) error {
	return c.post("/v0/remove", removeBody{Circle: c.Circle, Name: name}, nil)
}

// SetHost records that host (peer ID or connected member label) hosts
// name (registry override); "" clears.
func (c *Client) SetHost(name, host string) error {
	return c.post("/v0/hosts", hostBody{Circle: c.Circle, Name: name, Host: host}, nil)
}

// Append casts an event. Returns the (possibly derived) event ID and
// whether it was new.
func (c *Client) Append(name string, ev astral.Event) (id string, fresh bool, err error) {
	return c.append(name, ev, false)
}

// AppendRequest casts a request whose reply the caller will wait for and
// returns its ID: the handle for Outcome and Release. The host that
// journals the request keeps the reply with it; nothing is declared.
func (c *Client) AppendRequest(name string, ev astral.Event) (id string, err error) {
	id, _, err = c.append(name, ev, true)
	return id, err
}

func (c *Client) append(name string, ev astral.Event, reply bool) (id string, fresh bool, err error) {
	var r appendReply
	if c.Signer != nil && ev.ID == "" {
		ev.ID = NewEventID()
	}
	if err := c.post("/v0/append", appendBody{Principal: c.sign(OpAppend, name, ev.ID, "", appendDigestValue(ev, reply)), Circle: c.Circle, Name: name, Event: ev, Reply: reply}, &r); err != nil {
		return "", false, err
	}
	return r.ID, r.Fresh, nil
}

// Complete finishes a claimed request with its reply: the host records the
// reply and acknowledges the request in one write. It is how a worker
// finishes any request — delivered is false when no caller is waiting for
// the reply (none was wanted, or the caller is gone), and the request is
// acknowledged either way. A sub-key signs the reply here; the device's
// is signed by the daemon.
func (c *Client) Complete(name, requestID string, reply astral.Event) (delivered bool, err error) {
	reply.CorrelationID = requestID
	if c.Signer != nil && len(reply.Signature) == 0 {
		astral.SignReply(c.Signer.Priv, c.Signer.Key, astral.Ref{Circle: c.Circle, Name: name}, &reply)
	}
	var r completeReply
	err = c.post("/v0/complete", completeBody{Principal: c.sign(OpComplete, name, requestID, "", replyDigestValue(reply)), Circle: c.Circle, Name: name, EventID: requestID, Event: reply}, &r)
	return r.Delivered, err
}

// Outcome waits up to timeoutS seconds for the reply to a request this
// client published with AppendRequest; nil when there is none yet. The
// daemon has checked the reply before handing it on: its signature binds
// it to the request, and its signer was entitled to answer. Reading does
// not consume — call Release once the reply has been acted on.
func (c *Client) Outcome(name, requestID string, timeoutS int) (*astral.Event, error) {
	var r outcomeReply
	err := c.post("/v0/outcome", outcomeBody{Principal: c.sign(OpOutcome, name, requestID, "", ""), Circle: c.Circle, Name: name, EventID: requestID, TimeoutS: timeoutS}, &r)
	return r.Outcome, err
}

// Release tells the host the caller has its reply, or no longer wants one;
// the request stops counting against the caller's quota.
func (c *Client) Release(name, requestID string) error {
	return c.post("/v0/release", releaseBody{Principal: c.sign(OpRelease, name, requestID, "", ""), Circle: c.Circle, Name: name, EventID: requestID}, nil)
}

// Claim leases up to n events for lease seconds.
func (c *Client) Claim(name, consumer string, leaseS, n int) ([]astral.Claimed, error) {
	var out []astral.Claimed
	err := c.post("/v0/claim", claimBody{Principal: c.sign(OpClaim, name, "", consumer, ""), Circle: c.Circle, Name: name, Consumer: consumer, LeaseS: leaseS, N: n}, &out)
	return out, err
}

// Ack force-acks an event for consumer.
func (c *Client) Ack(name, consumer, eventID string) error {
	return c.post("/v0/ack", ackBody{Principal: c.sign(OpAck, name, eventID, consumer, ""), Circle: c.Circle, Name: name, Consumer: consumer, EventID: eventID}, nil)
}

// Set writes a register.
func (c *Client) Set(name, value string) error {
	return c.post("/v0/set", setBody{Principal: c.sign(OpSet, name, "", "", value), Circle: c.Circle, Name: name, Value: value}, nil)
}

// Get reads a register; ok=false when unset.
func (c *Client) Get(name string) (astral.Register, bool, error) {
	var r astral.Register
	if c.Signer != nil {
		data, err := json.Marshal(getBody{Principal: c.sign(OpGet, name, "", "", ""), Circle: c.Circle, Name: name})
		if err != nil {
			return r, false, err
		}
		resp, err := c.http.Post("http://astral/v0/get", "application/json", bytes.NewReader(data))
		if err != nil {
			return r, false, fmt.Errorf("is `fabric up` running? %w", err)
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return r, true, json.NewDecoder(resp.Body).Decode(&r)
		case http.StatusNotFound:
			return r, false, nil
		}
		return r, false, decodeErr(resp)
	}
	q := url.Values{"name": {name}}
	if c.Circle != "" {
		q.Set("circle", c.Circle)
	}
	resp, err := c.http.Get("http://astral/v0/get?" + q.Encode())
	if err != nil {
		return r, false, fmt.Errorf("is `fabric up` running? %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return r, true, json.NewDecoder(resp.Body).Decode(&r)
	case http.StatusNotFound:
		return r, false, nil
	}
	return r, false, decodeErr(resp)
}

// Wait parks until name has mail or timeoutS elapses (the timer wake).
func (c *Client) Wait(name string, timeoutS int) (Woke, error) {
	var r waitReply
	err := c.post("/v0/wait", waitBody{Principal: c.sign(OpWait, name, "", "", ""), Circle: c.Circle, Name: name, TimeoutS: timeoutS}, &r)
	return r.Woke, err
}

// Heartbeat extends entity's liveness lease by ttlS seconds.
func (c *Client) Heartbeat(entity string, ttlS int) error {
	return c.post("/v0/heartbeat", heartbeatBody{Principal: c.sign(OpHeartbeat, entity, "", "", ""), Circle: c.Circle, Entity: entity, TTLS: ttlS}, nil)
}

// Watch subscribes watcher (a subject) to entity's death notices.
func (c *Client) Watch(entity, watcher string) error {
	return c.post("/v0/watch", watchBody{Principal: c.sign(OpWatch, entity, "", watcher, ""), Circle: c.Circle, Entity: entity, Watcher: watcher}, nil)
}
