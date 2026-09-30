// The CLI works against one small store interface with two backends: the
// control-socket client when a daemon is running (which then owns the
// Pebble locks), a direct circle open otherwise. Same operations, same
// output — the daemon is a residency change, not a semantics change.
package cli

import (
	"fmt"
	"io"
	"sync"

	"ioa.rocks/fabric/vault/circle"
	"ioa.rocks/fabric/vault/daemon"
)

type store interface {
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
	Sub(bucket, mode string) error
	treeStore
	Close() error
}

// openStore picks the backend for a state dir.
func openStore(statePath string) (store, error) {
	if cl := daemon.TryClient(statePath); cl != nil {
		return clientStore{cl}, nil
	}
	c, err := circle.Open(statePath)
	if err != nil {
		return nil, err
	}
	return &directStore{c: c, handles: map[string]*circle.Handle{}}, nil
}

// clientStore adapts daemon.Client (adds the no-op Close).
type clientStore struct{ *daemon.Client }

func (clientStore) Close() error { return nil }

// directStore runs the same operations in-process.
type directStore struct {
	c       *circle.Circle
	mu      sync.Mutex
	handles map[string]*circle.Handle
}

func (s *directStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.handles {
		_ = h.Close()
	}
	return nil
}

func (s *directStore) handle(ref string) (*circle.Handle, error) {
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
		info := daemon.BucketInfo{ID: id, Name: b.Genesis.Name, Sub: s.c.Subscription(id)}
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
	_ = s.c.SetSubscription(h.ID(), circle.SubFull)
	return daemon.BucketInfo{ID: h.ID(), Name: h.Bucket.Genesis.Name, Sub: circle.SubFull}, nil
}

func (s *directStore) Sub(bucket, mode string) error {
	if mode == "none" {
		mode = circle.SubNone
	}
	id, err := s.c.ResolveBucketID(bucket)
	if err != nil {
		return err
	}
	return s.c.SetSubscription(id, mode)
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
