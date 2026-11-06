package circle

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"

	"ioa.rocks/fabric/keystore"
	"ioa.rocks/fabric/statement"
)

// The circle's key history (task single-writer-store (b); statement
// version 2). A circle's DID is its first key and never changes; the key
// that signs for it may: a handover (statement.TypeHandover) signed by the
// retiring key names the new one, and every root-issued statement of the
// new key carries the handovers in prf, so a verifier that knows only the
// DID walks to the signer. The circle directory keeps the history in
// handovers.cbor; the roster learns it from the file, from the
// statements it ingests and from the gossip, and refuses what a retired
// key signed after its handover — or anything it signed, when the
// handover declared it compromised.

const handoversFile = "handovers.cbor"

// HandoversPath is where the circle keeps its key history.
func (c *Circle) HandoversPath() string { return filepath.Join(c.Path, handoversFile) }

// Handovers loads the circle's key history, oldest first; a missing file
// is an empty history. Each handover is verified along the chain from the
// circle's DID key; a file that does not verify is an error.
func (c *Circle) Handovers() ([]*statement.Statement, error) {
	raw, err := os.ReadFile(c.HandoversPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list [][]byte
	if err := cbor.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", c.HandoversPath(), err)
	}
	roots := statement.NewDIDRoot(c.Config.DID)
	var out []*statement.Statement
	for _, item := range list {
		st, err := statement.Decode(item)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.HandoversPath(), err)
		}
		if _, err := roots.Learn(st); err != nil {
			return nil, fmt.Errorf("%s: %w", c.HandoversPath(), err)
		}
		out = append(out, st)
	}
	return out, nil
}

// DIDRoot is the circle as a statement.Roots with its key history loaded:
// what everything on this node judging the circle should share (the
// roster's roots).
func (c *Circle) DIDRoot() (*statement.DIDRoot, error) {
	hs, err := c.Handovers()
	if err != nil {
		return nil, err
	}
	return statement.NewDIDRootWith(c.Config.DID, hs...)
}

// RootProof is the latest handover the circle knows — what a statement
// signed with the circle's current key must ride — or nil when the key is
// the DID key.
func (c *Circle) RootProof() *statement.Statement {
	hs, err := c.Handovers()
	if err != nil || len(hs) == 0 {
		return nil
	}
	return hs[len(hs)-1]
}

// AddHandover records a handover learned from elsewhere (gossip, a peer's
// statement) in the circle's history file; it must extend the history
// known here. Reports whether the file changed.
func (c *Circle) AddHandover(st *statement.Statement) (bool, error) {
	roots, err := c.DIDRoot()
	if err != nil {
		return false, err
	}
	grew, err := roots.Learn(st)
	if err != nil || !grew {
		return false, err
	}
	return true, SaveHandovers(c.Path, roots.Handovers(c.Config.DID))
}

// SaveHandovers writes a circle directory's key history atomically.
func SaveHandovers(dir string, hs []*statement.Statement) error {
	list := make([][]byte, 0, len(hs))
	for _, h := range hs {
		raw, err := h.Bytes()
		if err != nil {
			return err
		}
		list = append(list, raw)
	}
	raw, err := encMode.Marshal(list)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, handoversFile)
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Rotate replaces the circle's signing key on this device: it signs a
// handover from the current key to a fresh one (chained on the previous
// handover), records it, and re-encrypts the key container with the new
// key under the same passphrase — the old key is gone from this device.
// compromised says the old key is not to be trusted at all (leaked): every
// admission it signed dies everywhere the handover reaches, and the owner
// re-admits by hand. Without it the rotation is clean: what the old key
// signed up to now stands until renewed, and renewals come from the new
// key. Other owner devices keep the old container and must re-join from a
// fresh export. Returns the handover, which the caller publishes.
func (c *Circle) Rotate(passphrase string, compromised bool, now time.Time) (*statement.Statement, error) {
	old, err := c.Unlock(passphrase)
	if err != nil {
		return nil, err
	}
	roots, err := c.DIDRoot()
	if err != nil {
		return nil, err
	}
	if cur := roots.Current(); cur != nil && !cur.Equal(old.Public()) {
		return nil, errors.New("this device's key container does not hold the circle's current key — re-join the circle from a fresh export before rotating")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	next := ed25519.NewKeyFromSeed(seed)
	h, err := statement.Handover(old, next.Public().(ed25519.PublicKey), c.Config.DID, compromised, now, roots.RootProof())
	if err != nil {
		return nil, err
	}
	if _, err := roots.Learn(h); err != nil {
		return nil, err
	}
	// History first, then the key: a crash between leaves a device whose
	// container holds a retired key, which Rotate and Unlock-based
	// commands refuse with a clear message, rather than a history the
	// device has no key for.
	if err := SaveHandovers(c.Path, roots.Handovers(c.Config.DID)); err != nil {
		return nil, err
	}
	tmp := keyPath(c.Path) + ".tmp"
	if err := keystore.SaveSeed(tmp, seed, passphrase); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, keyPath(c.Path)); err != nil {
		return nil, err
	}
	return h, nil
}

// Signer unlocks the circle's current key and returns it with the proof a
// root-issued statement of that key must ride: the one call every signing
// command makes.
func (c *Circle) Signer(passphrase string) (ed25519.PrivateKey, *statement.Statement, error) {
	priv, err := c.Unlock(passphrase)
	if err != nil {
		return nil, nil, err
	}
	roots, err := c.DIDRoot()
	if err != nil {
		return nil, nil, err
	}
	if cur := roots.Current(); cur != nil && !cur.Equal(priv.Public()) {
		return nil, nil, fmt.Errorf("circle %q: this device's key container does not hold the key the circle's history names as current (a key handed over from, or a container copied without the history) — re-join the circle from a fresh 'circle export' of a device holding the current key", c.Config.Name)
	}
	return priv, roots.RootProof(), nil
}
