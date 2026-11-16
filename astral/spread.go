package astral

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strings"

	"github.com/cockroachdb/pebble"
)

// Spread placement (ADR 0015): a name several nodes host at once. The
// registry keeps one record per host under `s/<ref>/<host>`, beside the
// single-host record `p/<ref>`. A name is one or the other, never both:
// whichever kind a node learned first refuses the other as a conflict, so
// two nodes that each declared the same private inbox still collide as
// before.

const (
	spreadLive     = "live"
	spreadDraining = "draining"
)

// Announced is one entry of a node's registry announcement.
type Announced struct {
	Ref
	Spread   bool
	Draining bool
}

// SetSpread turns spread placement on or off for a subject hosted here.
func (s *Store) SetSpread(ref Ref, on bool) error {
	return s.updateSubject(ref, func(m *Subject) error {
		if on && m.Delivery != DeliveryShared {
			return ErrSpreadPolicy
		}
		m.Spread = on
		return nil
	})
}

// SetDraining starts or ends a drain of a subject hosted here.
func (s *Store) SetDraining(ref Ref, on bool) error {
	return s.updateSubject(ref, func(m *Subject) error {
		m.Draining = on
		return nil
	})
}

func (s *Store) updateSubject(ref Ref, change func(*Subject) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m Subject
	if ok, err := s.getJSON(k1("m/", ref), &m); err != nil {
		return err
	} else if !ok {
		return s.unknownOrExpired(ref)
	}
	if err := change(&m); err != nil {
		return err
	}
	b := s.db.NewBatch()
	defer b.Close()
	if err := s.setJSON(b, k1("m/", ref), m); err != nil {
		return err
	}
	return b.Commit(pebble.Sync)
}

// SpreadHosts lists the remote hosts of a spread ref in rank order: the
// order every node computes alike, so publishers agree on the first choice
// without talking to each other.
func (s *Store) SpreadHosts(ref Ref) ([]Placement, error) {
	it, err := s.db.NewIter(prefixBounds(k1("s/", ref) + "/"))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []Placement
	for it.First(); it.Valid(); it.Next() {
		_, tail := mustParseKey(string(it.Key())[2:])
		out = append(out, Placement{Ref: ref, Host: strings.TrimPrefix(tail, "/"), Spread: true, Draining: string(it.Value()) == spreadDraining})
	}
	RankHosts(ref, out)
	return out, nil
}

// RankHosts orders the hosts of a ref by rendezvous hash: highest
// hash(ref, host) first. Adding or removing a host moves only the names
// that ranked it first.
func RankHosts(ref Ref, hosts []Placement) {
	score := func(host string) string {
		sum := sha256.Sum256([]byte(ref.key() + "\x00" + host))
		return string(sum[:])
	}
	sort.Slice(hosts, func(i, j int) bool { return score(hosts[i].Host) > score(hosts[j].Host) })
}

// Hosts lists every placement record, single-host and spread.
func (s *Store) Hosts() ([]Placement, error) {
	var out []Placement
	for _, prefix := range []string{"p/", "s/"} {
		it, err := s.db.NewIter(prefixBounds(prefix))
		if err != nil {
			return nil, err
		}
		for it.First(); it.Valid(); it.Next() {
			ref, tail := mustParseKey(string(it.Key())[2:])
			if prefix == "p/" {
				out = append(out, Placement{Ref: ref, Host: string(it.Value())})
			} else {
				out = append(out, Placement{Ref: ref, Host: strings.TrimPrefix(tail, "/"), Spread: true, Draining: string(it.Value()) == spreadDraining})
			}
		}
		if err := it.Close(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReplaceHost is ReplaceHosting for an announcement of single-host refs.
func (s *Store) ReplaceHost(host string, refs []Ref) error {
	placed := make([]Announced, len(refs))
	for i, ref := range refs {
		placed[i] = Announced{Ref: ref}
	}
	return s.ReplaceHosting(host, placed)
}

// ReplaceHosting atomically replaces every placement learned from host
// with its new announcement. Registry refreshes use replacement rather
// than additive updates so a subject that a node stopped hosting does not
// remain routable forever. Conflicts are per ref (memo §12.4) and reported
// in a *ConflictError while the rest land: a single-host ref another node
// holds, a single-host ref others already spread, or a spread ref another
// node holds alone. An invalid ref fails the whole call — that is a
// malformed announcement, not a contest.
func (s *Store) ReplaceHosting(host string, placed []Announced) error {
	if host == "" {
		return errors.New("astral: registry host required")
	}
	if strings.Contains(host, "/") {
		return errors.New("astral: registry host may not contain '/'")
	}
	for _, a := range placed {
		if err := a.Ref.Valid(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.db.NewBatch()
	defer b.Close()
	var conflicts []Ref
	var accepted []Announced
	for _, a := range placed {
		single, held, err := s.singleHost(a.Ref)
		if err != nil {
			return err
		}
		if held && single != host {
			conflicts = append(conflicts, a.Ref)
			continue
		}
		if !a.Spread {
			others, err := s.spreadByOthers(a.Ref, host)
			if err != nil {
				return err
			}
			if others {
				conflicts = append(conflicts, a.Ref)
				continue
			}
		}
		accepted = append(accepted, a)
	}
	for _, prefix := range []string{"p/", "s/"} {
		it, err := s.db.NewIter(prefixBounds(prefix))
		if err != nil {
			return err
		}
		for it.First(); it.Valid(); it.Next() {
			_, tail := mustParseKey(string(it.Key())[2:])
			mine := string(it.Value()) == host
			if prefix == "s/" {
				mine = strings.TrimPrefix(tail, "/") == host
			}
			if mine {
				if err := b.Delete(append([]byte(nil), it.Key()...), nil); err != nil {
					it.Close()
					return err
				}
			}
		}
		if err := it.Close(); err != nil {
			return err
		}
	}
	for _, a := range accepted {
		key, value := k1("p/", a.Ref), host
		if a.Spread {
			key, value = k2("s/", a.Ref, host), spreadLive
			if a.Draining {
				value = spreadDraining
			}
		}
		if err := b.Set([]byte(key), []byte(value), nil); err != nil {
			return err
		}
	}
	if err := b.Commit(pebble.Sync); err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &ConflictError{Refs: conflicts}
	}
	return nil
}

func (s *Store) singleHost(ref Ref) (string, bool, error) {
	raw, closer, err := s.db.Get([]byte(k1("p/", ref)))
	if errors.Is(err, pebble.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer closer.Close()
	return string(raw), true, nil
}

// spreadByOthers reports whether any node other than host spreads ref.
func (s *Store) spreadByOthers(ref Ref, host string) (bool, error) {
	it, err := s.db.NewIter(prefixBounds(k1("s/", ref) + "/"))
	if err != nil {
		return false, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		_, tail := mustParseKey(string(it.Key())[2:])
		if strings.TrimPrefix(tail, "/") != host {
			return true, nil
		}
	}
	return false, nil
}
