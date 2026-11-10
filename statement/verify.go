package statement

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"ioa.rocks/fabric/did"
)

// Roots answers "which root keys does this node honour for a circle DID".
// A DID is opaque here: it may later map to several keys or a threshold
// key. An empty answer means the circle is not held by this node.
type Roots interface {
	RootKeys(circleDID string) []ed25519.PublicKey
}

// RootMap is the simplest Roots.
type RootMap map[string][]ed25519.PublicKey

func (m RootMap) RootKeys(circleDID string) []ed25519.PublicKey { return m[circleDID] }

// RootHistory is a Roots that also knows a circle's key handovers
// (TypeHandover), oldest first. With it the verifier refuses what a
// retired key signed after its handover, and anything a key declared
// compromised signed; without it, a lineage's own handovers are the only
// history (what a node verifying for a circle it does not hold can do).
type RootHistory interface {
	Handovers(circleDID string) []*Statement
}

// Revocations answers "which revocations might concern this link": those
// targeting the link's ID, and those sweeping its recipient. Candidates must
// already be signature-checked (RevocationSet does that on Add); Check only
// applies rule 3's ancestry and target matching.
type Revocations interface {
	Candidates(id [32]byte, aud string) []*Statement
}

// Link is one compiled chain entry: what the cache keeps per link.
type Link struct {
	ID   [32]byte
	Iss  string
	Aud  string
	Sub  string
	Iat  int64
	Stmt *Statement
}

// Compiled holds the invariants of a verified pair of chains: the authority
// chain (what may be done, in circle Sub) and the optional identity chain
// (who presents). Nothing in it depends on now or on revocations; those are
// Check's business.
type Compiled struct {
	Sub            string       // circle of the authority chain
	PresentingKey  string       // did:key that must present: identity leaf aud, else authority leaf aud
	Nbf, Exp       time.Time    // max(nbf), min(exp) across both chains
	Auth           []Link       // root-first
	Ident          []Link       // root-first; empty when the presenter is the authority leaf's aud
	IdentAnchor    string       // circle DID the identity chain was anchored at through roots; "" when anchored at a did:key
	Handovers      []*Statement // key handovers the authority lineage carries, oldest first
	IdentHandovers []*Statement // and the identity lineage's, when anchored at a circle
	UnknownVerbs   []string     // verbs on the authority leaf this binary does not know
}

// AuthLeafID is the ID of the presented authority statement.
func (c *Compiled) AuthLeafID() [32]byte { return c.Auth[len(c.Auth)-1].ID }

// Want is one authorization question.
type Want struct {
	Sub           string
	Res           Resource
	Verb          string
	PresentingKey string // did:key of the connection peer or envelope signer
	Now           time.Time
}

// Compile verifies the structure of an authority chain and an optional
// identity chain for circle sub against the honoured roots: signatures,
// chaining, types, windows' shape, delegation depth, attenuation, overlay
// metadata (rule 7), admission authority (rule 8), anchoring of the identity
// chain (rules 1 and 5). It is the expensive half; cache the result per
// (connection, authority leaf, presenting key).
func Compile(authority, identity *Statement, sub string, roots Roots) (*Compiled, error) {
	if authority == nil {
		return nil, errors.New("no authority statement")
	}
	if sub == "" {
		return nil, errors.New("want.sub is empty")
	}
	auth := authority.Chain()
	// Rule 1 and 4: every authority link is in sub; the root link's issuer is
	// an honoured root for sub.
	for _, link := range auth {
		if link.Payload.Sub != sub {
			return nil, fmt.Errorf("authority link %s is in circle %q, want %q", link.IDHex()[:8], link.Payload.Sub, sub)
		}
	}
	compiled := &Compiled{Sub: sub, Handovers: auth[0].Handovers()}
	var err error
	if compiled.Auth, compiled.Nbf, compiled.Exp, err = compileChain(auth, roots.RootKeys(sub), sub, compiled.Handovers, "authority"); err != nil {
		return nil, err
	}
	if err := historyAllows(roots, sub, compiled.Handovers, auth[0]); err != nil {
		return nil, fmt.Errorf("authority root link: %w", err)
	}
	leaf := auth[len(auth)-1]
	for _, verb := range leaf.Payload.Verbs {
		if !KnownVerbs[verb] {
			compiled.UnknownVerbs = append(compiled.UnknownVerbs, verb)
		}
	}
	compiled.PresentingKey = leaf.Payload.Aud
	if identity == nil {
		return compiled, nil
	}

	// Identity chain: anchored at the authority leaf's aud (rule 1 note). A
	// circle DID this node holds resolves through roots and the chain must
	// start there (root → device → sub-key, every link checked). Anything
	// else must be a did:key — a device or bare key, or a foreign circle's
	// did:key — and the chain joins where that key appears: as the issuer
	// of the first link, or as the recipient of an interior link, in which
	// case the links above it (the presenter's own home chain, which this
	// node cannot judge and need not) are dropped and the suffix compiles
	// from the anchor (task §"Two chains, one join point"; agy review,
	// 2026-11-02).
	anchor := leaf.Payload.Aud
	ident := identity.Chain()
	identSub := ident[0].Payload.Sub
	for _, link := range ident {
		if link.Payload.Sub != identSub {
			return nil, errors.New("identity links span several circles")
		}
	}
	anchorKeys := roots.RootKeys(anchor)
	identHandovers := ident[0].Handovers()
	if len(anchorKeys) > 0 {
		compiled.IdentAnchor = anchor
		compiled.IdentHandovers = identHandovers
	} else {
		key, err := did.KeyFor(anchor)
		if err != nil {
			return nil, fmt.Errorf("identity anchor %q is neither a held circle nor a did:key", anchor)
		}
		anchorKeys = []ed25519.PublicKey{key}
		for i, link := range ident {
			if link.Payload.Aud == anchor {
				ident = ident[i+1:]
				identHandovers = nil // the suffix starts at a device key, not a circle's
				break
			}
		}
		if len(ident) == 0 {
			// The anchor is the last link's recipient: the presenter is the
			// anchor itself and the chain adds nothing.
			return compiled, nil
		}
	}
	links, identNbf, identExp, err := compileChain(ident, anchorKeys, identSub, identHandovers, "identity")
	if err != nil {
		return nil, err
	}
	if compiled.IdentAnchor != "" {
		if err := historyAllows(roots, anchor, identHandovers, ident[0]); err != nil {
			return nil, fmt.Errorf("identity root link: %w", err)
		}
	}
	compiled.Ident = links
	if identNbf.After(compiled.Nbf) {
		compiled.Nbf = identNbf
	}
	if identExp.Before(compiled.Exp) {
		compiled.Exp = identExp
	}
	compiled.PresentingKey = ident[len(ident)-1].Payload.Aud
	return compiled, nil
}

// compileChain checks one chain root-first. anchorKeys are the keys whose
// signature may stand at the top (the honoured roots of the circle, or the
// identity anchor), or from which the lineage's handovers must run to the
// key that does.
func compileChain(chain []*Statement, anchorKeys []ed25519.PublicKey, sub string, handovers []*Statement, what string) ([]Link, time.Time, time.Time, error) {
	if len(chain) > MaxDepth {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("%s chain deeper than %d", what, MaxDepth)
	}
	rootKeys, err := walkHandovers(handovers, anchorKeys, sub, true)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("%s key handovers: %w", what, err)
	}
	var links []Link
	var nbf, exp time.Time
	for i, link := range chain {
		payload := link.Payload
		id := link.IDHex()[:8]
		if payload.Typ != TypeAssert {
			return nil, nbf, exp, fmt.Errorf("%s link %s is not an assert", what, id)
		}
		if payload.Aud == "" {
			return nil, nbf, exp, fmt.Errorf("%s link %s has no recipient", what, id)
		}
		if err := link.VerifySignature(); err != nil {
			return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
		}
		// Rule 2 (shape): nbf < exp, window within MaxValidity.
		if payload.Nbf == 0 || payload.Exp <= payload.Nbf {
			return nil, nbf, exp, fmt.Errorf("%s link %s has no valid window", what, id)
		}
		if time.Duration(payload.Exp-payload.Nbf)*time.Second > MaxValidity || time.Duration(payload.Exp-payload.Iat)*time.Second > MaxValidity {
			return nil, nbf, exp, fmt.Errorf("%s link %s window exceeds MaxValidity", what, id)
		}
		if i == 0 {
			// Root-issued: the issuer must be one of the keys allowed on top.
			issKey, err := link.IssuerKey()
			if err != nil {
				return nil, nbf, exp, fmt.Errorf("%s root link: %w", what, err)
			}
			honoured := false
			for _, key := range rootKeys {
				if bytes.Equal(key, issKey) {
					honoured = true
					break
				}
			}
			if !honoured {
				return nil, nbf, exp, fmt.Errorf("%s root link %s is issued by a key this node does not honour for the circle", what, id)
			}
			nbf, exp = link.NotBefore(), link.Expiry()
		} else {
			parent := chain[i-1].Payload
			// Chaining.
			if payload.Iss != parent.Aud {
				return nil, nbf, exp, fmt.Errorf("%s link %s is not issued by its parent's recipient", what, id)
			}
			// Delegation depth: parent must allow a child, child strictly shallower.
			if parent.Del < 1 {
				return nil, nbf, exp, fmt.Errorf("%s link %s: parent is not delegable (del 0)", what, id)
			}
			if payload.Del >= parent.Del {
				return nil, nbf, exp, fmt.Errorf("%s link %s: del %d must be below the parent's %d", what, id, payload.Del, parent.Del)
			}
			// Attenuation: child verbs ⊆ parent verbs, child res ⊆ parent res.
			for _, verb := range payload.Verbs {
				if !verbAllows(parent.Verbs, verb) {
					return nil, nbf, exp, fmt.Errorf("%s link %s grants verb %q its parent does not hold", what, id, verb)
				}
			}
			for _, res := range payload.Res {
				if !resCovered(parent, payload.Sub, res) {
					return nil, nbf, exp, fmt.Errorf("%s link %s names resource %s/%s its parent does not cover", what, id, res.Kind, res.Name)
				}
			}
			// Rule 8: admission verbs and overlay metadata need an admission issuer.
			if needsAdmission(payload) && !hasVerb(parent.Verbs, VerbAdmin) {
				return nil, nbf, exp, fmt.Errorf("%s link %s carries admission verbs or overlay metadata but its issuer is not an admin", what, id)
			}
			// Rule 7: overlay fields against the immediate parent only.
			if err := checkOverlay(payload.Meta, parent.Meta, false); err != nil {
				return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
			}
			if link.NotBefore().After(nbf) {
				nbf = link.NotBefore()
			}
			if link.Expiry().Before(exp) {
				exp = link.Expiry()
			}
		}
		if i == 0 {
			if err := checkOverlay(payload.Meta, nil, true); err != nil {
				return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
			}
		}
		links = append(links, Link{ID: link.ID(), Iss: payload.Iss, Aud: payload.Aud, Sub: payload.Sub, Iat: payload.Iat, Stmt: link})
	}
	return links, nbf, exp, nil
}

// needsAdmission reports whether a link carries anything only the root or an
// admin may issue.
func needsAdmission(payload Payload) bool {
	for _, verb := range payload.Verbs {
		if admissionVerbs[verb] {
			return true
		}
	}
	return payload.Meta != nil && (payload.Meta.IP != "" || payload.Meta.Prefix != "")
}

// resCovered reports whether some resource of parent covers res as named in
// a child whose sub is childSub.
func resCovered(parent Payload, childSub string, res Resource) bool {
	for _, parentRes := range parent.Res {
		if parentRes.Covers(parent.Sub, res, childSub) {
			return true
		}
	}
	return false
}

// checkOverlay is rule 7. A root-issued link may carry anything well-formed.
// Otherwise ip must lie in the parent's prefix or equal the parent's ip,
// and prefix must lie in the parent's prefix.
func checkOverlay(meta, parent *Meta, rootIssued bool) error {
	if meta == nil {
		return nil
	}
	var ip netip.Prefix
	var prefix netip.Prefix
	var err error
	if meta.IP != "" {
		if ip, err = netip.ParsePrefix(meta.IP); err != nil {
			return fmt.Errorf("meta.ip: %w", err)
		}
	}
	if meta.Prefix != "" {
		if prefix, err = netip.ParsePrefix(meta.Prefix); err != nil {
			return fmt.Errorf("meta.prefix: %w", err)
		}
	}
	if rootIssued {
		return nil
	}
	if meta.IP != "" {
		ok := false
		if parent != nil && parent.Prefix != "" {
			if parentPrefix, err := netip.ParsePrefix(parent.Prefix); err == nil && parentPrefix.Contains(ip.Addr()) {
				ok = true
			}
		}
		if !ok && parent != nil && parent.IP != "" && parent.IP == meta.IP {
			ok = true // a sub-key inheriting its device's address
		}
		if !ok {
			return errors.New("meta.ip is outside the parent's prefix and not the parent's own ip")
		}
	}
	if meta.Prefix != "" {
		if parent == nil || parent.Prefix == "" {
			return errors.New("meta.prefix on a link whose parent has no prefix")
		}
		parentPrefix, err := netip.ParsePrefix(parent.Prefix)
		if err != nil || !parentPrefix.Contains(prefix.Addr()) || prefix.Bits() < parentPrefix.Bits() {
			return errors.New("meta.prefix is not inside the parent's prefix")
		}
	}
	return nil
}

// Allows is the scope question over the compiled chains: every authority
// link must cover (sub, res) with verb, and so must every identity link
// (a sub-key's assert enumerates what it may use; nothing is inherited
// wholesale). Unknown verbs are never allowed.
func (c *Compiled) Allows(sub string, res Resource, verb string) bool {
	if sub != c.Sub || !KnownVerbs[verb] {
		return false
	}
	for _, link := range c.Auth {
		if !linkAllows(link.Stmt.Payload, sub, res, verb) {
			return false
		}
	}
	for _, link := range c.Ident {
		if !linkAllows(link.Stmt.Payload, sub, res, verb) {
			return false
		}
	}
	return true
}

func linkAllows(payload Payload, sub string, res Resource, verb string) bool {
	if !verbAllows(payload.Verbs, verb) {
		return false
	}
	for _, linkRes := range payload.Res {
		if linkRes.Covers(payload.Sub, res, sub) {
			return true
		}
	}
	return false
}

// Check is the per-verb half: roots still honoured, presenter, window at
// now, scope, and revocations over both lineages. Errors say which rule
// failed.
//
// The root check is repeated here, cheaply (a key comparison, no
// signature), because a Compiled is meant to be cached: a chain compiled
// while its root was honoured must stop working the moment that root is
// retired (root-retired event), without waiting for the cache to notice
// (Codex review, 2026-11-02).
func (c *Compiled) Check(roots Roots, revs Revocations, want Want) error {
	if err := c.RootsHonoured(roots); err != nil {
		return err
	}
	if want.PresentingKey != c.PresentingKey {
		return fmt.Errorf("presented by %s, chain is for %s", short(want.PresentingKey), short(c.PresentingKey))
	}
	if want.Now.Before(c.Nbf) {
		return errors.New("chain not yet valid")
	}
	if !want.Now.Before(c.Exp) {
		return errors.New("chain expired")
	}
	if !c.Allows(want.Sub, want.Res, want.Verb) {
		return fmt.Errorf("chain does not grant %s on %s/%s in %s", want.Verb, want.Res.Kind, want.Res.Name, short(want.Sub))
	}
	return c.RevokedBy(roots, revs)
}

// RootsHonoured is the roots half of Check on its own: are both chains'
// roots still honoured — the circle held, its key history not retiring
// the signer before it signed. What makes a cached Compiled safe (see
// Check), and what a roster asks of every entry when the history grows.
func (c *Compiled) RootsHonoured(roots Roots) error {
	if err := honourRoot(roots, c.Sub, roots.RootKeys(c.Sub), c.Handovers, c.Auth[0].Stmt, false); err != nil {
		return fmt.Errorf("authority chain root is no longer honoured for the circle: %w", err)
	}
	if c.IdentAnchor != "" {
		keys := roots.RootKeys(c.IdentAnchor)
		if len(keys) == 0 {
			// The circle is no longer held here; as in Compile, a did:key
			// anchor still resolves on its own.
			if key, err := did.KeyFor(c.IdentAnchor); err == nil {
				keys = []ed25519.PublicKey{key}
			}
		}
		if err := honourRoot(roots, c.IdentAnchor, keys, c.IdentHandovers, c.Ident[0].Stmt, false); err != nil {
			return fmt.Errorf("identity chain anchor is no longer honoured: %w", err)
		}
	}
	return nil
}

// RevokedBy is the revocation half of Check on its own: rule 3 over both
// lineages. nil revs means no revocations are known.
func (c *Compiled) RevokedBy(roots Roots, revs Revocations) error {
	if revs == nil {
		return nil
	}
	if err := revoked(c.Auth, roots, revs); err != nil {
		return fmt.Errorf("authority %w", err)
	}
	if err := revoked(c.Ident, roots, revs); err != nil {
		return fmt.Errorf("identity %w", err)
	}
	return nil
}

// revoked applies rule 3 to one lineage, root-first: a revocation kills link
// i if it targets it (by id; by aud as a removal the link does not
// acknowledge; by aud as a legacy sweep with iat <= before) and either is
// root-signed for the link's circle, or rides a chain whose leaf is a link
// strictly above i in this very lineage. The acknowledgment rule is the
// cascade of ADR 0019: removing an admin kills what it admitted, and a
// sub-key under an admission that never saw its device's removal stays
// dead after the device is restored.
func revoked(links []Link, roots Roots, revs Revocations) error {
	for i, link := range links {
		for _, rev := range revs.Candidates(link.ID, link.Aud) {
			if !targets(rev, link) || rev.Payload.Sub != link.Sub {
				continue
			}
			if rev.IsRootIssued() {
				// The revocation's own lineage signatures were checked at
				// RevocationSet.Add; here its handovers are walked and the
				// node's history applied, as for any root-issued statement.
				if honourRoot(roots, link.Sub, rootKeysOrDID(roots, link.Sub), rev.Handovers(), rev, false) == nil {
					return fmt.Errorf("link %s revoked by the root", short(link.Aud))
				}
				continue
			}
			leaf := rev.Parent()
			if leaf.Payload.Aud != rev.Payload.Iss {
				continue
			}
			leafID := leaf.ID()
			for j := 0; j < i; j++ {
				if links[j].ID == leafID {
					return fmt.Errorf("link %s revoked by %s", short(link.Aud), short(rev.Payload.Iss))
				}
			}
		}
	}
	return nil
}

func targets(rev *Statement, link Link) bool {
	target := rev.Payload.Target
	if target == nil || rev.Payload.Typ != TypeRevoke {
		return false
	}
	if len(target.ID) != 0 {
		return bytes.Equal(target.ID, link.ID[:])
	}
	if target.Aud != link.Aud {
		return false
	}
	if rev.Payload.V < 2 {
		return link.Iat <= target.Before // legacy sweep: the cut rule, never an acknowledgment
	}
	return !link.Stmt.Acknowledges(rev.ID())
}

// rootKeysOrDID resolves a circle's root keys through roots, falling back
// to the did:key itself for a circle this node does not hold — so a root
// revocation on an identity link in a foreign circle (the presenter's home
// root revoking its device) is recognised, as Compile recognises that root.
func rootKeysOrDID(roots Roots, circleDID string) []ed25519.PublicKey {
	if keys := roots.RootKeys(circleDID); len(keys) > 0 {
		return keys
	}
	if key, err := did.KeyFor(circleDID); err == nil {
		return []ed25519.PublicKey{key}
	}
	return nil
}

func rootSigned(stmt *Statement, rootKeys []ed25519.PublicKey) bool {
	issKey, err := stmt.IssuerKey()
	if err != nil {
		return false
	}
	for _, rootKey := range rootKeys {
		if bytes.Equal(rootKey, issKey) {
			return true
		}
	}
	return false
}

// walkHandovers checks that a lineage's handovers run from one of
// anchorKeys to one current key, each signed by the key it retires (when
// sigs), each for circle sub, and returns the keys a root-issued statement
// of that lineage may be signed with: the last handover's recipient, or
// anchorKeys when there is none.
func walkHandovers(handovers []*Statement, anchorKeys []ed25519.PublicKey, sub string, sigs bool) ([]ed25519.PublicKey, error) {
	if len(handovers) > MaxHandovers {
		return nil, fmt.Errorf("more than MaxHandovers %d", MaxHandovers)
	}
	keys := anchorKeys
	for i, handover := range handovers {
		if handover.Payload.Typ != TypeHandover {
			return nil, errors.New("not a handover")
		}
		if handover.Payload.Sub != sub {
			return nil, fmt.Errorf("handover %d is for circle %s, not %s", i, short(handover.Payload.Sub), short(sub))
		}
		if err := handoverShape(handover.Payload); err != nil {
			return nil, fmt.Errorf("handover %d: %w", i, err)
		}
		if !rootSigned(handover, keys) {
			if i == 0 {
				return nil, errors.New("the first handover is not signed by the circle's key")
			}
			return nil, fmt.Errorf("handover %d is not signed by the key the previous one handed over to", i)
		}
		if sigs {
			if err := handover.VerifySignature(); err != nil {
				return nil, fmt.Errorf("handover %d: %w", i, err)
			}
		}
		key, err := did.KeyFor(handover.Payload.Aud)
		if err != nil {
			return nil, fmt.Errorf("handover %d: %w", i, err)
		}
		keys = []ed25519.PublicKey{key}
	}
	return keys, nil
}

// historyAllows applies the node's known key history (RootHistory, when
// roots has one) to a root-issued statement stmt whose lineage carries the
// handovers: the two histories must agree where they overlap, and when
// the node knows a handover the lineage does not — one that retired stmt's
// signer — stmt must have been issued no later than that handover, and the
// handover must not have declared the key compromised. A lineage that
// knows more than the node is honoured on its own proof; the holder learns
// it from the statement (DIDRoot.Learn) outside the verifier.
func historyAllows(roots Roots, sub string, handovers []*Statement, stmt *Statement) error {
	history, ok := roots.(RootHistory)
	if !ok {
		return nil
	}
	known := history.Handovers(sub)
	for i := 0; i < len(known) && i < len(handovers); i++ {
		if known[i].ID() != handovers[i].ID() {
			return ErrConflictingHandover
		}
	}
	if len(known) <= len(handovers) {
		return nil
	}
	retiring := known[len(handovers)]
	if retiring.Payload.Compromised {
		return errors.New("signed by a key the circle declared compromised")
	}
	if stmt.Payload.Iat > retiring.Payload.Iat {
		return errors.New("signed by a retired key after its handover")
	}
	return nil
}

// SigningKeys is the set of keys that may sign for circle sub at the
// instant at, under the key history roots knows: the current key, and a
// retired key for what it signed no later than its handover — never a key
// the handover declared compromised. The rule historyAllows applies to a
// statement, for records that carry no proof of their own (the
// membership-event log; the roster's sweeps, which remember their
// signer).
func SigningKeys(roots Roots, sub string, at int64) []ed25519.PublicKey {
	anchor := roots.RootKeys(sub)
	history, ok := roots.(RootHistory)
	if !ok {
		return anchor
	}
	handovers := history.Handovers(sub)
	if len(handovers) == 0 {
		return anchor
	}
	var out []ed25519.PublicKey
	epochKeys := [][]ed25519.PublicKey{anchor}
	for _, handover := range handovers {
		if key, err := did.KeyFor(handover.Payload.Aud); err == nil {
			epochKeys = append(epochKeys, []ed25519.PublicKey{key})
		}
	}
	for i, keys := range epochKeys {
		if i < len(handovers) {
			retiring := handovers[i]
			if retiring.Payload.Compromised || at > retiring.Payload.Iat {
				continue
			}
		}
		out = append(out, keys...)
	}
	return out
}

// KeyHonouredAt reports whether the key keyDID (a did:key) is one of
// SigningKeys for circle sub at the instant at.
func KeyHonouredAt(roots Roots, sub, keyDID string, at int64) bool {
	key, err := did.KeyFor(keyDID)
	if err != nil {
		return false
	}
	for _, candidate := range SigningKeys(roots, sub, at) {
		if candidate.Equal(key) {
			return true
		}
	}
	return false
}

// honourRoot is the whole root check for a root-issued statement stmt of
// circle sub: its lineage's handovers run from anchorKeys to its
// signer, and the node's history allows it. sigs re-verifies the
// handovers' signatures (Compile does; Check and the revocation pass rely
// on what was verified at compile or ingest).
func honourRoot(roots Roots, sub string, anchorKeys []ed25519.PublicKey, handovers []*Statement, stmt *Statement, sigs bool) error {
	keys, err := walkHandovers(handovers, anchorKeys, sub, sigs)
	if err != nil {
		return err
	}
	if !rootSigned(stmt, keys) {
		return errors.New("not signed by the circle's key")
	}
	return historyAllows(roots, sub, handovers, stmt)
}

// RootSigned reports whether a parentless statement of circle sub is
// signed by the circle's root as roots knows it: by the anchor key, or by
// the current key through the handovers the statement carries, within the
// node's history. Signatures are verified.
func RootSigned(roots Roots, sub string, stmt *Statement) bool {
	if stmt == nil || !stmt.IsRootIssued() {
		return false
	}
	if err := stmt.VerifySignature(); err != nil {
		return false
	}
	return honourRoot(roots, sub, rootKeysOrDID(roots, sub), stmt.Handovers(), stmt, true) == nil
}

// Verify is Compile followed by Check: the whole §6 checklist in one call,
// for callers that do not cache.
func Verify(authority, identity *Statement, roots Roots, revs Revocations, want Want) (*Compiled, error) {
	compiled, err := Compile(authority, identity, want.Sub, roots)
	if err != nil {
		return nil, err
	}
	if err := compiled.Check(roots, revs, want); err != nil {
		return nil, err
	}
	return compiled, nil
}

func short(text string) string {
	if len(text) > 16 {
		return text[:16] + "…"
	}
	return text
}
