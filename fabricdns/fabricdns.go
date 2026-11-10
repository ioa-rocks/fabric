// Package fabricdns answers `<member>.fabric` — the mesh's own name
// service. The zone is the member store: every cert carries a name and an
// overlay IP, both signed by the root key, so resolution needs no
// extra state, no coordination, and no external DNS. The server binds the
// node's own overlay address (it exists exactly when the TUN bridge is up)
// and answers only for the .fabric suffix; everything else is refused so a
// misconfigured resolver fails fast to its next upstream.
package fabricdns

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Suffix is the mesh TLD, without dots.
const Suffix = "fabric"

const ttl = 30 // seconds; membership changes should propagate quickly

// Lookup resolves a bare member name ("nas") to its overlay address.
type Lookup func(host string) (netip.Addr, bool)

// Server is a tiny authoritative resolver for the .fabric zone.
type Server struct {
	lookup Lookup
	udp    *dns.Server
	tcp    *dns.Server
}

// New builds the server; Serve starts it.
func New(lookup Lookup) *Server { return &Server{lookup: lookup} }

// Serve listens on addr ("100.64.0.1:53") over UDP and TCP until Close.
// The returned error channel reports listener startup failure.
func (s *Server) Serve(addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errc := make(chan error, 2)
	started := make(chan struct{}, 2)
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		srv.NotifyStartedFunc = func() { started <- struct{}{} }
		go func(srv *dns.Server) { errc <- srv.ListenAndServe() }(srv)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case err := <-errc:
			s.Close()
			return fmt.Errorf("dns listener on %s: %w", addr, err)
		case <-time.After(5 * time.Second):
			s.Close()
			return fmt.Errorf("dns listener on %s: startup timeout", addr)
		}
	}
	return nil
}

// Close stops both listeners.
func (s *Server) Close() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func (s *Server) handle(writer dns.ResponseWriter, req *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Authoritative = true

	for _, question := range req.Question {
		name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		host, ok := strings.CutSuffix(name, "."+Suffix)
		if !ok || host == "" || strings.Contains(host, ".") {
			reply.Rcode = dns.RcodeRefused // not our zone (or a subdomain we don't do)
			continue
		}
		ip, found := s.lookup(host)
		if !found {
			reply.Rcode = dns.RcodeNameError
			continue
		}
		// A answered; AAAA (and anything else) gets an empty NOERROR so
		// dual-stack resolvers settle on the A record without retries.
		if question.Qtype == dns.TypeA && ip.Is4() {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.AsSlice(),
			})
		}
	}
	_ = writer.WriteMsg(reply)
}
