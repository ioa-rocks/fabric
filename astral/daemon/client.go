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
type Client struct {
	Circle string
	http   http.Client
}

// NewClient builds a client for a state dir's control socket.
func NewClient(statePath string) *Client {
	sock := SocketPath(statePath)
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
// TTL and a total-append cap (zero keeps each unlimited — except for
// ephemeral `_reply/` names, which default to tight limits either way).
func (c *Client) DeclareExpiring(name string, delivery astral.Delivery, accepts []string, idle time.Duration, maxEvents int) error {
	return c.post("/v0/subjects", declareBody{
		Circle: c.Circle, Name: name, Delivery: delivery, Accepts: accepts,
		IdleS: int(idle / time.Second), MaxEv: maxEvents,
	}, nil)
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
	var r appendReply
	if err := c.post("/v0/append", appendBody{Circle: c.Circle, Name: name, Event: ev}, &r); err != nil {
		return "", false, err
	}
	return r.ID, r.Fresh, nil
}

// Claim leases up to n events for lease seconds.
func (c *Client) Claim(name, consumer string, leaseS, n int) ([]astral.Claimed, error) {
	var out []astral.Claimed
	err := c.post("/v0/claim", claimBody{Circle: c.Circle, Name: name, Consumer: consumer, LeaseS: leaseS, N: n}, &out)
	return out, err
}

// Ack force-acks an event for consumer.
func (c *Client) Ack(name, consumer, eventID string) error {
	return c.post("/v0/ack", ackBody{Circle: c.Circle, Name: name, Consumer: consumer, EventID: eventID}, nil)
}

// Set writes a register.
func (c *Client) Set(name, value string) error {
	return c.post("/v0/set", setBody{Circle: c.Circle, Name: name, Value: value}, nil)
}

// Get reads a register; ok=false when unset.
func (c *Client) Get(name string) (astral.Register, bool, error) {
	var r astral.Register
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
	err := c.post("/v0/wait", waitBody{Circle: c.Circle, Name: name, TimeoutS: timeoutS}, &r)
	return r.Woke, err
}

// Heartbeat extends entity's liveness lease by ttlS seconds.
func (c *Client) Heartbeat(entity string, ttlS int) error {
	return c.post("/v0/heartbeat", heartbeatBody{Circle: c.Circle, Entity: entity, TTLS: ttlS}, nil)
}

// Watch subscribes watcher (a subject) to entity's death notices.
func (c *Client) Watch(entity, watcher string) error {
	return c.post("/v0/watch", watchBody{Circle: c.Circle, Entity: entity, Watcher: watcher}, nil)
}
