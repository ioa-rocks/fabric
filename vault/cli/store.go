// The CLI works against one small store interface with two backends: the
// control-socket client when a daemon is running (which then owns the
// Pebble locks), a direct circle open otherwise. Same operations, same
// output — the daemon is a residency change, not a semantics change.
package cli

import (
	"fmt"
	"io"
	"ioa.rocks/fabric/circle"
	"sync"

	"ioa.rocks/fabric/vault/daemon"
	"ioa.rocks/fabric/vault/store"
)

// store_ is the CLI's view of a store; the package name is taken.
type store_ interface {
	Buckets() ([]daemon.BucketInfo, error)
	CreateBucket(genesis, policy []byte) (daemon.BucketInfo, error)
	List(bucket string, tags []string) ([]daemon.ObjectInfo, error)
	Put(bucket, name string, r io.Reader, tags []string) (daemon.ObjectInfo, error)
	Get(bucket, ref string) (io.ReadCloser, error)
	Replace(bucket, ref string, r io.Reader) (daemon.ObjectInfo, error)
	Rename(bucket, ref, name string) (daemon.ObjectInfo, error)
	Tag(bucket, ref string, add, remove []string) (daemon.ObjectInfo, error)
	Rm(bucket, ref string) (daemon.ObjectInfo, error)
	Project(bucket, dir string) (int, error)
	// Place sets the placement mode; root, when non-nil, also sets the
	// blob store root ("" or "default" = the default store).
	Place(bucket, mode string, root *string) error
	treeStore
	Close() error
}

// openStore picks the backend: the daemon's socket when one serves the
// store directory, a direct open (which needs the circle) otherwise.
func openStore(p paths) (store_, error) {
	if cl := daemon.TryClient(*p.store); cl != nil {
		return clientStore{cl}, nil
	}
	if _, err := circle.Migrate(*p.circle, *p.store); err != nil {
		return nil, fmt.Errorf("adopting the circle from %s: %w", *p.store, err)
	}
	if !circle.Any(*p.circle) {
		return nil, fmt.Errorf("no daemon on %s and this node holds no circle (did you run 'fabric circle init'?)", daemon.SocketPath(*p.store))
	}
	st, err := store.Open(*p.store, *p.circle)
	if err != nil {
		return nil, err
	}
	return &directStore{c: st, handles: map[string]*store.Handle{}}, nil
}

// clientStore adapts daemon.Client (adds the no-op Close).
type clientStore struct{ *daemon.Client }

func (clientStore) Close() error { return nil }

func (s clientStore) Place(bucket, mode string, root *string) error {
	if root == nil {
		return s.Client.Sub(bucket, mode)
	}
	return s.Client.SubAt(bucket, mode, *root)
}

// directStore runs the same operations in-process.
type directStore struct {
	c       *store.Store
	mu      sync.Mutex
	handles map[string]*store.Handle
}

func (s *directStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.handles {
		_ = h.Close()
	}
	return nil
}

func (s *directStore) handle(ref string) (*store.Handle, error) {
	id, err := s.c.ResolveBucketID(ref)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.handles[id]; ok {
		return h, nil
	}
	h, err := s.c.OpenBucket(id)
	if err != nil {
		return nil, fmt.Errorf("%w (a stopped daemon may have crashed holding the lock)", err)
	}
	s.handles[id] = h
	return h, nil
}

func (s *directStore) Buckets() ([]daemon.BucketInfo, error) {
	buckets, err := s.c.Buckets()
	if err != nil {
		return nil, err
	}
	var out []daemon.BucketInfo
	for _, b := range buckets {
		id, err := b.ID()
		if err != nil {
			continue
		}
		pl := s.c.Placement(id)
		info := daemon.BucketInfo{ID: id, Owner: b.Genesis.Owner, Name: b.Genesis.Name, Sub: pl.Mode, Root: pl.Root}
		if h, err := s.handle(id); err == nil {
			info.Objects, info.Held, _ = h.Stats()
		}
		out = append(out, info)
	}
	return out, nil
}

func (s *directStore) CreateBucket(genesis, policy []byte) (daemon.BucketInfo, error) {
	h, err := s.c.AdoptBucket(genesis, policy)
	if err != nil {
		return daemon.BucketInfo{}, err
	}
	s.mu.Lock()
	s.handles[h.ID()] = h
	s.mu.Unlock()
	// Same default as the daemon path: the creating device holds what it
	// puts.
	_ = s.c.SetSubscription(h.ID(), store.SubFull)
	return daemon.BucketInfo{ID: h.ID(), Owner: h.Bucket.Genesis.Owner, Name: h.Bucket.Genesis.Name, Sub: store.SubFull}, nil
}

func (s *directStore) Place(bucket, mode string, root *string) error {
	if mode == "none" {
		mode = store.SubNone
	}
	id, err := s.c.ResolveBucketID(bucket)
	if err != nil {
		return err
	}
	pl := s.c.Placement(id)
	pl.Mode = mode
	if root != nil {
		pl.Root = *root
		if pl.Root == "default" {
			pl.Root = ""
		}
	}
	return s.c.SetPlacement(id, pl)
}

func (s *directStore) List(bucket string, tags []string) ([]daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return nil, err
	}
	objs, err := h.Index.ListObjects(tags...)
	if err != nil {
		return nil, err
	}
	var out []daemon.ObjectInfo
	for _, o := range objs {
		if _, err := h.BackfillSize(o); err != nil {
			return nil, err
		}
		out = append(out, daemon.Info(o))
	}
	return out, nil
}

func (s *directStore) Put(bucket, name string, r io.Reader, tags []string) (daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.Put(name, r, tags...)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(o), nil
}

func (s *directStore) Get(bucket, ref string) (io.ReadCloser, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return nil, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return nil, err
	}
	return h.Get(o)
}

func (s *directStore) Replace(bucket, ref string, r io.Reader) (daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err = h.Replace(o, r)
	return daemon.Info(o), err
}

func (s *directStore) Rename(bucket, ref, name string) (daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err = h.Rename(o, name)
	return daemon.Info(o), err
}

func (s *directStore) Tag(bucket, ref string, add, remove []string) (daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if o, err = h.Tag(o, add, remove); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(o), nil
}

func (s *directStore) Rm(bucket, ref string) (daemon.ObjectInfo, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	o, err := h.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if err := h.Delete(o); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(o), nil
}

func (s *directStore) Project(bucket, dir string) (int, error) {
	h, err := s.handle(bucket)
	if err != nil {
		return 0, err
	}
	return h.Project(dir)
}
