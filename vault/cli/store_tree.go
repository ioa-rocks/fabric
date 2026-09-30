package cli

import (
	"ioa.rocks/fabric/vault/bucket"
	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

// treeStore is the ADR 0001 half of the store interface: policy revisions,
// trash, conflicts and held deletions. daemon.Client implements it over the
// control socket; directStore in-process.
type treeStore interface {
	Policy(bucket string) (bucket.Policy, error)
	SetPolicy(bucket string, policyRaw []byte) (bucket.Policy, error)
	Trash(bucket string) ([]daemon.ObjectInfo, error)
	Restore(bucket, ref string) (daemon.ObjectInfo, error)
	Conflicts(bucket string) ([]daemon.ConflictEntry, error)
	Resolve(bucket, ref string) (daemon.ObjectInfo, error)
	Held(bucket string) ([]daemon.HeldEntry, error)
	AcceptHeld(bucket string) (int, error)
	RejectHeld(bucket string) (int, error)
}

func (s *directStore) Policy(name string) (bucket.Policy, error) {
	h, err := s.handle(name)
	if err != nil {
		return bucket.Policy{}, err
	}
	return h.CurrentPolicy(), nil
}

func (s *directStore) SetPolicy(name string, policyRaw []byte) (bucket.Policy, error) {
	h, err := s.handle(name)
	if err != nil {
		return bucket.Policy{}, err
	}
	if _, err := h.UpdatePolicy(policyRaw); err != nil {
		return bucket.Policy{}, err
	}
	return h.CurrentPolicy(), nil
}

func (s *directStore) Trash(name string) ([]daemon.ObjectInfo, error) {
	h, err := s.handle(name)
	if err != nil {
		return nil, err
	}
	objs, err := h.Trash()
	if err != nil {
		return nil, err
	}
	out := []daemon.ObjectInfo{}
	for _, o := range objs {
		out = append(out, daemon.Info(o))
	}
	return out, nil
}

func (s *directStore) Restore(name, ref string) (daemon.ObjectInfo, error) {
	h, err := s.handle(name)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveTrashed(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if o, err = h.Restore(o); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(o), nil
}

func (s *directStore) Conflicts(name string) ([]daemon.ConflictEntry, error) {
	h, err := s.handle(name)
	if err != nil {
		return nil, err
	}
	cs, err := h.Conflicts()
	if err != nil {
		return nil, err
	}
	return daemon.ConflictEntries(cs), nil
}

func (s *directStore) Resolve(name, ref string) (daemon.ObjectInfo, error) {
	h, err := s.handle(name)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if o, err = h.Resolve(o); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(o), nil
}

func (s *directStore) Held(name string) ([]daemon.HeldEntry, error) {
	h, err := s.handle(name)
	if err != nil {
		return nil, err
	}
	list, err := h.ListHeld()
	if err != nil {
		return nil, err
	}
	out := []daemon.HeldEntry{}
	for _, e := range list {
		out = append(out, daemon.HeldEntry{ID: e.ID, Name: e.Name, From: e.From, FirstSeen: e.FirstSeen})
	}
	return out, nil
}

func (s *directStore) AcceptHeld(name string) (int, error) {
	return s.decide(name, (*store.Handle).AcceptHeld)
}

func (s *directStore) RejectHeld(name string) (int, error) {
	return s.decide(name, (*store.Handle).RejectHeld)
}

func (s *directStore) decide(name string, fn func(*store.Handle) (int, error)) (int, error) {
	h, err := s.handle(name)
	if err != nil {
		return 0, err
	}
	return fn(h)
}
