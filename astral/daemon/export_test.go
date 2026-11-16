package daemon

import "ioa.rocks/fabric/astral"

// ForgetOrigins drops what this daemon remembers about which host each
// event of a spread name is on, as a restart does.
func (d *Daemon) ForgetOrigins() {
	d.origins.mu.Lock()
	defer d.origins.mu.Unlock()
	d.origins.m = map[originKey]originAt{}
}

// AppendSigned publishes ev under an envelope the caller built, the way a
// daemon between a sub-key and the host could: nothing here checks that
// the envelope was signed for this event.
func (c *Client) AppendSigned(name string, ev astral.Event, pr *astral.Principal) error {
	return c.post("/v0/append", appendBody{Principal: pr, Circle: c.Circle, Name: name, Event: ev}, nil)
}
