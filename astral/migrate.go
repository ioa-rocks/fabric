package astral

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cockroachdb/pebble"
)

// Layout is the store layout version written at v/layout. Layout 2 keys
// every resource by (circle, name); layout 1 (absent marker) keyed by bare
// name.
const Layout = 2

const layoutKey = "v/layout"

// Migrate rewrites a layout-1 store under home: every bare-name key becomes
// the same resource in the home circle (the degenerate case of memo §12.3:
// before this step the one mesh was the one circle). Learned placements are
// dropped rather than rewritten — they held member labels, layout 2 holds
// peer IDs, and the next registry exchange re-learns them. Idempotent:
// a store already at Layout returns 0.
func (s *Store) Migrate(home string) (int, error) {
	if err := validCircle(home); err != nil {
		return 0, err
	}
	var have int
	if ok, err := s.getJSON(layoutKey, &have); err != nil {
		return 0, err
	} else if ok && have >= Layout {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	it, err := s.db.NewIter(nil)
	if err != nil {
		return 0, err
	}
	b := s.db.NewBatch()
	defer b.Close()
	n := 0
	for it.First(); it.Valid(); it.Next() {
		key := string(it.Key())
		if len(key) < 2 || key[1] != '/' || key == layoutKey {
			continue
		}
		prefix, rest := key[:2], key[2:]
		if isLayout2(rest) {
			continue
		}
		var newKey string
		var value []byte
		switch prefix {
		case "m/", "t/", "x/", "r/":
			newKey = k1(prefix, Ref{Circle: home, Name: rest})
			value = append([]byte(nil), it.Value()...)
			if prefix == "m/" || prefix == "r/" {
				// The JSON gains its circle field.
				var obj map[string]any
				if err := json.Unmarshal(value, &obj); err != nil {
					it.Close()
					return n, fmt.Errorf("migrating %s: %w", key, err)
				}
				obj["circle"] = home
				if value, err = json.Marshal(obj); err != nil {
					it.Close()
					return n, err
				}
			}
		case "e/", "i/", "a/", "l/", "o/":
			i := strings.LastIndexByte(rest, '/')
			if i < 0 {
				continue
			}
			newKey = k2(prefix, Ref{Circle: home, Name: rest[:i]}, rest[i+1:])
			value = append([]byte(nil), it.Value()...)
		case "h/":
			newKey = k1(prefix, Ref{Circle: home, Name: rest})
			var obj map[string]any
			if err := json.Unmarshal(it.Value(), &obj); err != nil {
				it.Close()
				return n, fmt.Errorf("migrating %s: %w", key, err)
			}
			obj["circle"] = home
			if value, err = json.Marshal(obj); err != nil {
				it.Close()
				return n, err
			}
		case "w/":
			entity, watcher, ok := strings.Cut(rest, "/")
			if !ok {
				continue
			}
			newKey = k2(prefix, Ref{Circle: home, Name: entity}, Ref{Circle: home, Name: watcher}.key())
			value = []byte{}
		case "p/":
			// Dropped: label-valued, re-learned on the next exchange.
		default:
			continue
		}
		if err := b.Delete([]byte(key), nil); err != nil {
			it.Close()
			return n, err
		}
		if newKey != "" {
			if err := b.Set([]byte(newKey), value, nil); err != nil {
				it.Close()
				return n, err
			}
		}
		n++
	}
	if err := it.Close(); err != nil {
		return n, err
	}
	raw, err := json.Marshal(Layout)
	if err != nil {
		return n, err
	}
	if err := b.Set([]byte(layoutKey), raw, nil); err != nil {
		return n, err
	}
	return n, b.Commit(pebble.Sync)
}

// isLayout2 reports whether a key remainder (after the 2-byte prefix) is
// already circle-keyed: its first segment is a circle id, never a bare
// `subject:`/`register:` name or an entity.
func isLayout2(rest string) bool {
	seg, _, _ := strings.Cut(rest, "/")
	if seg == LocalCircle || strings.HasPrefix(seg, "did:") {
		_, _, ok := parseKey(rest)
		return ok
	}
	return false
}

// ErrLayout reports a store newer than this binary understands.
var ErrLayout = errors.New("astral: store layout is newer than this binary")

// CheckLayout refuses a store written by a newer layout.
func (s *Store) CheckLayout() error {
	var have int
	if ok, err := s.getJSON(layoutKey, &have); err != nil {
		return err
	} else if ok && have > Layout {
		return fmt.Errorf("%w (%d > %d)", ErrLayout, have, Layout)
	}
	return nil
}
