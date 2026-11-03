package astral

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Ref names a resource of a circle: a subject, a register or a monitored
// entity. The circle DID is part of the identity (overlapping-circles memo
// §12.4, §17): two circles may both have a `subject:jobs`, and a node that
// hosts for several circles keeps them apart. Nothing in the plane is
// addressed by a bare name any more; the wire, the store and the registry
// all carry the pair.
type Ref struct {
	Circle string `json:"circle" cbor:"c"`
	Name   string `json:"name" cbor:"n"`
}

// LocalCircle stands in for the circle on a node that is not on any mesh
// (solo mode, unit tests): the plane still needs a key.
const LocalCircle = "local"

// String is the display form: the bare name for callers that know the
// circle, otherwise `<name> @ <circle>`.
func (r Ref) String() string {
	if r.Circle == "" {
		return r.Name
	}
	return r.Name + " @ " + r.Circle
}

// Ephemeral reports whether this is a temporary reply subject.
func (r Ref) Ephemeral() bool { return Ephemeral(r.Name) }

// ErrBadCircle is a circle id the store cannot key by.
var ErrBadCircle = errors.New("astral: circle required (a did:key, no '/')")

// validCircle: non-empty, no separator.
func validCircle(c string) error {
	if c == "" || strings.ContainsAny(c, "/ ") {
		return ErrBadCircle
	}
	return nil
}

// Valid checks the pair as a subject reference.
func (r Ref) Valid() error {
	if err := validCircle(r.Circle); err != nil {
		return err
	}
	return ValidName(r.Name)
}

// key is the storage form: `<circle>/<len>:<name>`. The length prefix is
// what keeps `subject:a` and `subject:a/b` apart under prefix iteration —
// with bare names, every range for the first also covered the second.
func (r Ref) key() string {
	return r.Circle + "/" + strconv.Itoa(len(r.Name)) + ":" + r.Name
}

// parseKey reads a key produced by Ref.key from the front of s and returns
// the ref and whatever follows the name (e.g. "/<seq>", or "" for a
// single-level key).
func parseKey(s string) (Ref, string, bool) {
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return Ref{}, "", false
	}
	circle, rest := s[:slash], s[slash+1:]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return Ref{}, "", false
	}
	n, err := strconv.Atoi(rest[:colon])
	if err != nil || n < 0 || len(rest) < colon+1+n {
		return Ref{}, "", false
	}
	name := rest[colon+1 : colon+1+n]
	return Ref{Circle: circle, Name: name}, rest[colon+1+n:], true
}

// mustParseKey is parseKey for keys the store wrote itself.
func mustParseKey(s string) (Ref, string) {
	r, rest, ok := parseKey(s)
	if !ok {
		panic(fmt.Sprintf("astral: malformed store key %q", s))
	}
	return r, rest
}

// ValidID rejects event IDs that would break the `<key>/<id>` layout.
func ValidID(id string) error {
	if strings.ContainsRune(id, '/') {
		return fmt.Errorf("astral: event id %q may not contain '/'", id)
	}
	return nil
}
