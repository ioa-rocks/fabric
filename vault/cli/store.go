// The CLI works against one small store interface with two backends: the
// control-socket client when a daemon is running (which then owns the
// Pebble locks), a direct circle open otherwise. Same operations, same
// output — the daemon is a residency change, not a semantics change.
package cli

import (
	"errors"
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
	Put(bucket, name string, reader io.Reader, tags []string) (daemon.ObjectInfo, error)
	Get(bucket, ref string) (io.ReadCloser, error)
	Replace(bucket, ref string, reader io.Reader) (daemon.ObjectInfo, error)
	Rename(bucket, ref, name string) (daemon.ObjectInfo, error)
	Tag(bucket, ref string, add, remove []string) (daemon.ObjectInfo, error)
	Rm(bucket, ref string) (daemon.ObjectInfo, error)
	Project(bucket, dir string) (int, error)
	// Place sets the placement mode; root, when non-nil, also sets the
	// blob store root ("" or "default" = the default store).
	// keep, when non-nil, sets a cache placement's budget in bytes.
	Place(bucket, mode string, root *string, keep *int64) error
	treeStore
	Close() error
}

// openStore picks the backend: the daemon's socket when one serves the
// store directory, a direct open (which needs the circle) otherwise.
func openStore(pth paths) (store_, error) {
	if cl := daemon.TryClient(*pth.store); cl != nil {
		return clientStore{cl}, nil
	}
	if !circle.Any(*pth.circle) {
		return nil, fmt.Errorf("no daemon on %s and this node holds no circle (did you run 'fabric circle init'?)", daemon.SocketPath(*pth.store))
	}
	st, err := store.Open(*pth.store, *pth.circle)
	if err != nil {
		return nil, err
	}
	return &directStore{c: st, handles: map[string]*store.Handle{}}, nil
}

// clientStore adapts daemon.Client (adds the no-op Close).
type clientStore struct{ *daemon.Client }

func (clientStore) Close() error { return nil }

func (s clientStore) Place(bucket, mode string, root *string, keep *int64) error {
	return s.Client.Place(bucket, mode, root, keep)
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
	for _, handle := range s.handles {
		_ = handle.Close()
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
	if handle, ok := s.handles[id]; ok {
		return handle, nil
	}
	handle, err := s.c.OpenBucket(id)
	if err != nil {
		return nil, fmt.Errorf("%w (a stopped daemon may have crashed holding the lock)", err)
	}
	s.handles[id] = handle
	return handle, nil
}

func (s *directStore) Buckets() ([]daemon.BucketInfo, error) {
	buckets, err := s.c.Buckets()
	if err != nil {
		return nil, err
	}
	var out []daemon.BucketInfo
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil {
			continue
		}
		pl := s.c.Placement(id)
		info := daemon.BucketInfo{ID: id, Owner: bkt.Genesis.Owner, Name: bkt.Genesis.Name, Sub: pl.Mode, Root: pl.Root, Keep: pl.Keep}
		if handle, err := s.handle(id); err == nil {
			info.Objects, info.Files, info.Held, _ = handle.Stats()
		}
		out = append(out, info)
	}
	return out, nil
}

func (s *directStore) CreateBucket(genesis, policy []byte) (daemon.BucketInfo, error) {
	handle, err := s.c.AdoptBucket(genesis, policy)
	if err != nil {
		return daemon.BucketInfo{}, err
	}
	s.mu.Lock()
	s.handles[handle.ID()] = handle
	s.mu.Unlock()
	// Same default as the daemon path: the creating device holds what it
	// puts.
	_ = s.c.SetSubscription(handle.ID(), store.SubFull)
	return daemon.BucketInfo{ID: handle.ID(), Owner: handle.Bucket.Genesis.Owner, Name: handle.Bucket.Genesis.Name, Sub: store.SubFull}, nil
}

func (s *directStore) Place(bucket, mode string, root *string, keep *int64) error {
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
	if keep != nil {
		if *keep > 0 && mode != store.SubCache {
			return errors.New("a budget applies to a cache placement")
		}
		pl.Keep = *keep
	}
	return s.c.SetPlacement(id, pl)
}

func (s *directStore) List(bucket string, tags []string) ([]daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return nil, err
	}
	objs, err := handle.Index.ListObjects(tags...)
	if err != nil {
		return nil, err
	}
	var out []daemon.ObjectInfo
	for _, obj := range objs {
		if _, err := handle.BackfillSize(obj); err != nil {
			return nil, err
		}
		out = append(out, daemon.Info(obj))
	}
	return out, nil
}

func (s *directStore) Put(bucket, name string, reader io.Reader, tags []string) (daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err := handle.Put(name, reader, tags...)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(obj), nil
}

func (s *directStore) Get(bucket, ref string) (io.ReadCloser, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return nil, err
	}
	obj, err := handle.ResolveObject(ref)
	if err != nil {
		return nil, err
	}
	return handle.Get(obj)
}

func (s *directStore) Replace(bucket, ref string, reader io.Reader) (daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err := handle.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err = handle.Replace(obj, reader)
	return daemon.Info(obj), err
}

func (s *directStore) Rename(bucket, ref, name string) (daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err := handle.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err = handle.Rename(obj, name)
	return daemon.Info(obj), err
}

func (s *directStore) Tag(bucket, ref string, add, remove []string) (daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err := handle.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if obj, err = handle.Tag(obj, add, remove); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(obj), nil
}

func (s *directStore) Rm(bucket, ref string) (daemon.ObjectInfo, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	obj, err := handle.ResolveObject(ref)
	if err != nil {
		return daemon.ObjectInfo{}, err
	}
	if err := handle.Delete(obj); err != nil {
		return daemon.ObjectInfo{}, err
	}
	return daemon.Info(obj), nil
}

func (s *directStore) Project(bucket, dir string) (int, error) {
	handle, err := s.handle(bucket)
	if err != nil {
		return 0, err
	}
	return handle.Project(dir)
}
