package daemon

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"ioa.rocks/fabric/circle"
	"ioa.rocks/fabric/did"
	"ioa.rocks/fabric/state"
	"ioa.rocks/fabric/statement"
)

// HomeSigner is what the legacy master commands (`approve`, `renew`, the
// web UI) need before signing with the root key container: the home
// circle's DID, and the proof a statement of the circle's current key must
// ride — its latest handover, nil when the key is the DID key. It refuses
// a container holding a key the circle has handed over from (`circle
// rotate` rewrites the root container with the circle's; a restored backup
// may not have it).
func HomeSigner(dir state.Dir, rootPriv ed25519.PrivateKey) (circleDID string, proof *statement.Statement, err error) {
	keyDID := did.ForKey(rootPriv.Public().(ed25519.PublicKey))
	cfg, err := dir.LoadConfig()
	if err != nil || cfg.CircleDID == "" {
		return keyDID, nil, nil
	}
	held, err := circle.ByDID(circle.Root(dir.Path), cfg.CircleDID)
	if err != nil {
		return cfg.CircleDID, nil, nil // no circle directory: the key is the circle
	}
	roots, err := held.DIDRoot()
	if err != nil {
		return "", nil, fmt.Errorf("circle %q key history: %w", held.Config.Name, err)
	}
	if cur := roots.Current(); cur != nil && !cur.Equal(rootPriv.Public()) {
		return "", nil, fmt.Errorf("the root key container holds a key circle %q has handed over from — rotate rewrote it; restore the container from a device holding the current key", held.Config.Name)
	}
	return held.Config.DID, roots.RootProof(), nil
}

// RevokeDevice signs the home circle's removal of a device with the root
// key — what `fabric revoke` and the web UI's revoke do (before 2026-11-07
// they signed a member-revoked event) — and records it in the circle
// directory. The caller has the daemon push it (Client.CircleRefresh).
func RevokeDevice(dir state.Dir, rootPriv ed25519.PrivateKey, deviceDID string, now time.Time) (*circle.Revocation, error) {
	circleDID, proof, err := HomeSigner(dir, rootPriv)
	if err != nil {
		return nil, err
	}
	held, err := circle.ByDID(circle.Root(dir.Path), circleDID)
	if err != nil {
		return nil, fmt.Errorf("this node holds no directory for circle %s (start the daemon once): %w", circleDID, err)
	}
	revocation, err := circle.RevokeIn(rootPriv, proof, circleDID, deviceDID, now)
	if err != nil {
		return nil, err
	}
	if _, err := held.AddRevocations(now, revocation); err != nil {
		return nil, err
	}
	return revocation, nil
}
