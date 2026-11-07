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
	for _, l := range auth {
		if l.Payload.Sub != sub {
			return nil, fmt.Errorf("authority link %s is in circle %q, want %q", l.IDHex()[:8], l.Payload.Sub, sub)
		}
	}
	c := &Compiled{Sub: sub, Handovers: auth[0].Handovers()}
	var err error
	if c.Auth, c.Nbf, c.Exp, err = compileChain(auth, roots.RootKeys(sub), sub, c.Handovers, "authority"); err != nil {
		return nil, err
	}
	if err := historyAllows(roots, sub, c.Handovers, auth[0]); err != nil {
		return nil, fmt.Errorf("authority root link: %w", err)
	}
	leaf := auth[len(auth)-1]
	for _, v := range leaf.Payload.Verbs {
		if !KnownVerbs[v] {
			c.UnknownVerbs = append(c.UnknownVerbs, v)
		}
	}
	c.PresentingKey = leaf.Payload.Aud
	if identity == nil {
		return c, nil
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
	isub := ident[0].Payload.Sub
	for _, l := range ident {
		if l.Payload.Sub != isub {
			return nil, errors.New("identity links span several circles")
		}
	}
	anchorKeys := roots.RootKeys(anchor)
	identHandovers := ident[0].Handovers()
	if len(anchorKeys) > 0 {
		c.IdentAnchor = anchor
		c.IdentHandovers = identHandovers
	} else {
		k, err := did.KeyFor(anchor)
		if err != nil {
			return nil, fmt.Errorf("identity anchor %q is neither a held circle nor a did:key", anchor)
		}
		anchorKeys = []ed25519.PublicKey{k}
		for i, l := range ident {
			if l.Payload.Aud == anchor {
				ident = ident[i+1:]
				identHandovers = nil // the suffix starts at a device key, not a circle's
				break
			}
		}
		if len(ident) == 0 {
			// The anchor is the last link's recipient: the presenter is the
			// anchor itself and the chain adds nothing.
			return c, nil
		}
	}
	links, inbf, iexp, err := compileChain(ident, anchorKeys, isub, identHandovers, "identity")
	if err != nil {
		return nil, err
	}
	if c.IdentAnchor != "" {
		if err := historyAllows(roots, anchor, identHandovers, ident[0]); err != nil {
			return nil, fmt.Errorf("identity root link: %w", err)
		}
	}
	c.Ident = links
	if inbf.After(c.Nbf) {
		c.Nbf = inbf
	}
	if iexp.Before(c.Exp) {
		c.Exp = iexp
	}
	c.PresentingKey = ident[len(ident)-1].Payload.Aud
	return c, nil
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
	for i, l := range chain {
		p := l.Payload
		id := l.IDHex()[:8]
		if p.Typ != TypeAssert {
			return nil, nbf, exp, fmt.Errorf("%s link %s is not an assert", what, id)
		}
		if p.Aud == "" {
			return nil, nbf, exp, fmt.Errorf("%s link %s has no recipient", what, id)
		}
		if err := l.VerifySignature(); err != nil {
			return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
		}
		// Rule 2 (shape): nbf < exp, window within MaxValidity.
		if p.Nbf == 0 || p.Exp <= p.Nbf {
			return nil, nbf, exp, fmt.Errorf("%s link %s has no valid window", what, id)
		}
		if time.Duration(p.Exp-p.Nbf)*time.Second > MaxValidity || time.Duration(p.Exp-p.Iat)*time.Second > MaxValidity {
			return nil, nbf, exp, fmt.Errorf("%s link %s window exceeds MaxValidity", what, id)
		}
		if i == 0 {
			// Root-issued: the issuer must be one of the keys allowed on top.
			issKey, err := l.IssuerKey()
			if err != nil {
				return nil, nbf, exp, fmt.Errorf("%s root link: %w", what, err)
			}
			honoured := false
			for _, k := range rootKeys {
				if bytes.Equal(k, issKey) {
					honoured = true
					break
				}
			}
			if !honoured {
				return nil, nbf, exp, fmt.Errorf("%s root link %s is issued by a key this node does not honour for the circle", what, id)
			}
			nbf, exp = l.NotBefore(), l.Expiry()
		} else {
			parent := chain[i-1].Payload
			// Chaining.
			if p.Iss != parent.Aud {
				return nil, nbf, exp, fmt.Errorf("%s link %s is not issued by its parent's recipient", what, id)
			}
			// Delegation depth: parent must allow a child, child strictly shallower.
			if parent.Del < 1 {
				return nil, nbf, exp, fmt.Errorf("%s link %s: parent is not delegable (del 0)", what, id)
			}
			if p.Del >= parent.Del {
				return nil, nbf, exp, fmt.Errorf("%s link %s: del %d must be below the parent's %d", what, id, p.Del, parent.Del)
			}
			// Attenuation: child verbs ⊆ parent verbs, child res ⊆ parent res.
			for _, v := range p.Verbs {
				if !verbAllows(parent.Verbs, v) {
					return nil, nbf, exp, fmt.Errorf("%s link %s grants verb %q its parent does not hold", what, id, v)
				}
			}
			for _, r := range p.Res {
				if !resCovered(parent, p.Sub, r) {
					return nil, nbf, exp, fmt.Errorf("%s link %s names resource %s/%s its parent does not cover", what, id, r.Kind, r.Name)
				}
			}
			// Rule 8: admission verbs and overlay metadata need an admission issuer.
			if needsAdmission(p) && !hasVerb(parent.Verbs, VerbAdmin) {
				return nil, nbf, exp, fmt.Errorf("%s link %s carries admission verbs or overlay metadata but its issuer is not an admin", what, id)
			}
			// Rule 7: overlay fields against the immediate parent only.
			if err := checkOverlay(p.Meta, parent.Meta, false); err != nil {
				return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
			}
			if l.NotBefore().After(nbf) {
				nbf = l.NotBefore()
			}
			if l.Expiry().Before(exp) {
				exp = l.Expiry()
			}
		}
		if i == 0 {
			if err := checkOverlay(p.Meta, nil, true); err != nil {
				return nil, nbf, exp, fmt.Errorf("%s link %s: %w", what, id, err)
			}
		}
		links = append(links, Link{ID: l.ID(), Iss: p.Iss, Aud: p.Aud, Sub: p.Sub, Iat: p.Iat, Stmt: l})
	}
	return links, nbf, exp, nil
}

// needsAdmission reports whether a link carries anything only the root or an
// admin may issue.
func needsAdmission(p Payload) bool {
	for _, v := range p.Verbs {
		if admissionVerbs[v] {
			return true
		}
	}
	return p.Meta != nil && (p.Meta.IP != "" || p.Meta.Prefix != "")
}

// resCovered reports whether some resource of parent covers r as named in
// a child whose sub is childSub.
func resCovered(parent Payload, childSub string, r Resource) bool {
	for _, pr := range parent.Res {
		if pr.Covers(parent.Sub, r, childSub) {
			return true
		}
	}
	return false
}

// checkOverlay is rule 7. A root-issued link may carry anything well-formed.
// Otherwise ip must lie in the parent's prefix or equal the parent's ip,
// and prefix must lie in the parent's prefix.
func checkOverlay(m, parent *Meta, rootIssued bool) error {
	if m == nil {
		return nil
	}
	var ip netip.Prefix
	var prefix netip.Prefix
	var err error
	if m.IP != "" {
		if ip, err = netip.ParsePrefix(m.IP); err != nil {
			return fmt.Errorf("meta.ip: %w", err)
		}
	}
	if m.Prefix != "" {
		if prefix, err = netip.ParsePrefix(m.Prefix); err != nil {
			return fmt.Errorf("meta.prefix: %w", err)
		}
	}
	if rootIssued {
		return nil
	}
	if m.IP != "" {
		ok := false
		if parent != nil && parent.Prefix != "" {
			if pp, err := netip.ParsePrefix(parent.Prefix); err == nil && pp.Contains(ip.Addr()) {
				ok = true
			}
		}
		if !ok && parent != nil && parent.IP != "" && parent.IP == m.IP {
			ok = true // a sub-key inheriting its device's address
		}
		if !ok {
			return errors.New("meta.ip is outside the parent's prefix and not the parent's own ip")
		}
	}
	if m.Prefix != "" {
		if parent == nil || parent.Prefix == "" {
			return errors.New("meta.prefix on a link whose parent has no prefix")
		}
		pp, err := netip.ParsePrefix(parent.Prefix)
		if err != nil || !pp.Contains(prefix.Addr()) || prefix.Bits() < pp.Bits() {
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
	for _, l := range c.Auth {
		if !linkAllows(l.Stmt.Payload, sub, res, verb) {
			return false
		}
	}
	for _, l := range c.Ident {
		if !linkAllows(l.Stmt.Payload, sub, res, verb) {
			return false
		}
	}
	return true
}

func linkAllows(p Payload, sub string, res Resource, verb string) bool {
	if !verbAllows(p.Verbs, verb) {
		return false
	}
	for _, r := range p.Res {
		if r.Covers(p.Sub, res, sub) {
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
			if k, err := did.KeyFor(c.IdentAnchor); err == nil {
				keys = []ed25519.PublicKey{k}
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
	for i, l := range links {
		for _, r := range revs.Candidates(l.ID, l.Aud) {
			if !targets(r, l) || r.Payload.Sub != l.Sub {
				continue
			}
			if r.IsRootIssued() {
				// The revocation's own lineage signatures were checked at
				// RevocationSet.Add; here its handovers are walked and the
				// node's history applied, as for any root-issued statement.
				if honourRoot(roots, l.Sub, rootKeysOrDID(roots, l.Sub), r.Handovers(), r, false) == nil {
					return fmt.Errorf("link %s revoked by the root", short(l.Aud))
				}
				continue
			}
			leaf := r.Parent()
			if leaf.Payload.Aud != r.Payload.Iss {
				continue
			}
			leafID := leaf.ID()
			for j := 0; j < i; j++ {
				if links[j].ID == leafID {
					return fmt.Errorf("link %s revoked by %s", short(l.Aud), short(r.Payload.Iss))
				}
			}
		}
	}
	return nil
}

func targets(r *Statement, l Link) bool {
	t := r.Payload.Target
	if t == nil || r.Payload.Typ != TypeRevoke {
		return false
	}
	if len(t.ID) != 0 {
		return bytes.Equal(t.ID, l.ID[:])
	}
	if t.Aud != l.Aud {
		return false
	}
	if r.Payload.V < 2 {
		return l.Iat <= t.Before // legacy sweep: the cut rule, never an acknowledgment
	}
	return !l.Stmt.Acknowledges(r.ID())
}

// rootKeysOrDID resolves a circle's root keys through roots, falling back
// to the did:key itself for a circle this node does not hold — so a root
// revocation on an identity link in a foreign circle (the presenter's home
// root revoking its device) is recognised, as Compile recognises that root.
func rootKeysOrDID(roots Roots, circleDID string) []ed25519.PublicKey {
	if keys := roots.RootKeys(circleDID); len(keys) > 0 {
		return keys
	}
	if k, err := did.KeyFor(circleDID); err == nil {
		return []ed25519.PublicKey{k}
	}
	return nil
}

func rootSigned(r *Statement, rootKeys []ed25519.PublicKey) bool {
	k, err := r.IssuerKey()
	if err != nil {
		return false
	}
	for _, rk := range rootKeys {
		if bytes.Equal(rk, k) {
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
func walkHandovers(hs []*Statement, anchorKeys []ed25519.PublicKey, sub string, sigs bool) ([]ed25519.PublicKey, error) {
	if len(hs) > MaxHandovers {
		return nil, fmt.Errorf("more than MaxHandovers %d", MaxHandovers)
	}
	keys := anchorKeys
	for i, h := range hs {
		if h.Payload.Typ != TypeHandover {
			return nil, errors.New("not a handover")
		}
		if h.Payload.Sub != sub {
			return nil, fmt.Errorf("handover %d is for circle %s, not %s", i, short(h.Payload.Sub), short(sub))
		}
		if err := handoverShape(h.Payload); err != nil {
			return nil, fmt.Errorf("handover %d: %w", i, err)
		}
		if !rootSigned(h, keys) {
			if i == 0 {
				return nil, errors.New("the first handover is not signed by the circle's key")
			}
			return nil, fmt.Errorf("handover %d is not signed by the key the previous one handed over to", i)
		}
		if sigs {
			if err := h.VerifySignature(); err != nil {
				return nil, fmt.Errorf("handover %d: %w", i, err)
			}
		}
		k, err := did.KeyFor(h.Payload.Aud)
		if err != nil {
			return nil, fmt.Errorf("handover %d: %w", i, err)
		}
		keys = []ed25519.PublicKey{k}
	}
	return keys, nil
}

// historyAllows applies the node's known key history (RootHistory, when
// roots has one) to a root-issued statement st whose lineage carries the
// handovers hs: the two histories must agree where they overlap, and when
// the node knows a handover the lineage does not — one that retired st's
// signer — st must have been issued no later than that handover, and the
// handover must not have declared the key compromised. A lineage that
// knows more than the node is honoured on its own proof; the holder learns
// it from the statement (DIDRoot.Learn) outside the verifier.
func historyAllows(roots Roots, sub string, hs []*Statement, st *Statement) error {
	h, ok := roots.(RootHistory)
	if !ok {
		return nil
	}
	known := h.Handovers(sub)
	for i := 0; i < len(known) && i < len(hs); i++ {
		if known[i].ID() != hs[i].ID() {
			return ErrConflictingHandover
		}
	}
	if len(known) <= len(hs) {
		return nil
	}
	retiring := known[len(hs)]
	if retiring.Payload.Compromised {
		return errors.New("signed by a key the circle declared compromised")
	}
	if st.Payload.Iat > retiring.Payload.Iat {
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
	h, ok := roots.(RootHistory)
	if !ok {
		return anchor
	}
	hs := h.Handovers(sub)
	if len(hs) == 0 {
		return anchor
	}
	var out []ed25519.PublicKey
	epochKeys := [][]ed25519.PublicKey{anchor}
	for _, ho := range hs {
		if k, err := did.KeyFor(ho.Payload.Aud); err == nil {
			epochKeys = append(epochKeys, []ed25519.PublicKey{k})
		}
	}
	for i, ks := range epochKeys {
		if i < len(hs) {
			retiring := hs[i]
			if retiring.Payload.Compromised || at > retiring.Payload.Iat {
				continue
			}
		}
		out = append(out, ks...)
	}
	return out
}

// KeyHonouredAt reports whether the key keyDID (a did:key) is one of
// SigningKeys for circle sub at the instant at.
func KeyHonouredAt(roots Roots, sub, keyDID string, at int64) bool {
	k, err := did.KeyFor(keyDID)
	if err != nil {
		return false
	}
	for _, c := range SigningKeys(roots, sub, at) {
		if c.Equal(k) {
			return true
		}
	}
	return false
}

// honourRoot is the whole root check for a root-issued statement st of
// circle sub: its lineage's handovers hs run from anchorKeys to its
// signer, and the node's history allows it. sigs re-verifies the
// handovers' signatures (Compile does; Check and the revocation pass rely
// on what was verified at compile or ingest).
func honourRoot(roots Roots, sub string, anchorKeys []ed25519.PublicKey, hs []*Statement, st *Statement, sigs bool) error {
	keys, err := walkHandovers(hs, anchorKeys, sub, sigs)
	if err != nil {
		return err
	}
	if !rootSigned(st, keys) {
		return errors.New("not signed by the circle's key")
	}
	return historyAllows(roots, sub, hs, st)
}

// RootSigned reports whether a parentless statement of circle sub is
// signed by the circle's root as roots knows it: by the anchor key, or by
// the current key through the handovers the statement carries, within the
// node's history. Signatures are verified.
func RootSigned(roots Roots, sub string, st *Statement) bool {
	if st == nil || !st.IsRootIssued() {
		return false
	}
	if err := st.VerifySignature(); err != nil {
		return false
	}
	return honourRoot(roots, sub, rootKeysOrDID(roots, sub), st.Handovers(), st, true) == nil
}

// Verify is Compile followed by Check: the whole §6 checklist in one call,
// for callers that do not cache.
func Verify(authority, identity *Statement, roots Roots, revs Revocations, want Want) (*Compiled, error) {
	c, err := Compile(authority, identity, want.Sub, roots)
	if err != nil {
		return nil, err
	}
	if err := c.Check(roots, revs, want); err != nil {
		return nil, err
	}
	return c, nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}
