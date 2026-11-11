package daemon

import (
	"context"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"ioa.rocks/fabric/statement"
)

// PlaceProtocol lets a device ask another how it holds the buckets the two
// share: full, cache (and its budget) or not at all, and how much of each
// is there. It exists for the operator's view — which bucket is configured
// how on which device — and nothing decides on it: the answer is unsigned
// and only as good as the moment it was given. Drop-safety asks its own
// question (HoldProtocol), and the signed, gossiped placement record of the
// placement-record memo is still to come.
const PlaceProtocol = "/vault/place/1"

// placeMaxAge is how long the answers of the peers stand before the next
// listing asks again.
var placeMaxAge = 10 * time.Second

// placeLimit bounds the buckets taken from one answer.
const placeLimit = 4096

type placeReq struct{}

type placeEntry struct {
	Bucket  string `cbor:"bucket"`
	Mode    string `cbor:"mode"` // "full" | "cache" | "" (none)
	Folder  bool   `cbor:"folder,omitempty"`
	Keep    int64  `cbor:"keep,omitempty"`
	Objects int    `cbor:"objects"`
	// Files is how many of the objects have content; Held counts among
	// those. A peer on the first release of this protocol sends no Files
	// and counts every object without content as held.
	Files *int `cbor:"files,omitempty"`
	Held  int  `cbor:"held"`
}

type placeResp struct {
	Places []placeEntry `cbor:"places"`
}

// PeerPlacement is how another device holds a bucket, as it last said.
type PeerPlacement struct {
	PeerID    string `json:"peer_id"`
	Name      string `json:"name,omitempty"`
	Mode      string `json:"mode"` // "full" | "cache" | "" (none)
	Folder    bool   `json:"folder,omitempty"`
	Keep      int64  `json:"keep,omitempty"`
	Objects   int    `json:"objects"`
	Files     int    `json:"files"` // objects with content; Held counts among these
	Held      int    `json:"held"`
	Connected bool   `json:"connected"`
	At        int64  `json:"at"` // when it answered, Unix nanoseconds
}

// peerPlaces is one peer's last answer.
type peerPlaces struct {
	name   string
	at     time.Time
	places map[string]placeEntry // bucket ID -> placement
}

// handlePlace tells a peer how this device holds each bucket that peer may
// sync. A bucket it may not sync is not mentioned.
func (d *Daemon) handlePlace(stream network.Stream) {
	defer stream.Close()
	if !d.begin() {
		return
	}
	defer d.end()
	_ = stream.SetDeadline(time.Now().Add(time.Minute))
	var req placeReq
	if err := cbor.NewDecoder(stream).Decode(&req); err != nil {
		stream.Reset()
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 20*time.Second)
	defer cancel()
	_ = cbor.NewEncoder(stream).Encode(placeResp{Places: d.placesFor(ctx, stream.Conn().RemotePeer())})
}

func (d *Daemon) placesFor(ctx context.Context, peerID peer.ID) []placeEntry {
	buckets, err := d.Store.Buckets()
	if err != nil {
		return nil
	}
	folders, _ := d.Store.Folders()
	var places []placeEntry
	for _, bkt := range buckets {
		id, err := bkt.ID()
		if err != nil || !d.peerMay(ctx, peerID, bkt.Genesis.Owner, id, statement.VerbSync) {
			continue
		}
		placement := d.Store.Placement(id)
		entry := placeEntry{Bucket: id, Mode: placement.Mode, Keep: placement.Keep}
		for _, folderDecl := range folders {
			if folderDecl.Bucket == id {
				entry.Folder = true
			}
		}
		if handle, err := d.handle(id); err == nil {
			if summary, err := handle.Summary(); err == nil {
				entry.Objects, entry.Files, entry.Held = summary.Objects, &summary.Files, summary.Held
			}
		}
		places = append(places, entry)
	}
	return places
}

// askPlaces asks one peer how it holds the shared buckets.
func (d *Daemon) askPlaces(peerID peer.ID) (map[string]placeEntry, error) {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	stream, err := d.Fabric.Host.NewStream(ctx, peerID, PlaceProtocol)
	cancel()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := cbor.NewEncoder(stream).Encode(placeReq{}); err != nil {
		return nil, err
	}
	var resp placeResp
	if err := cbor.NewDecoder(stream).Decode(&resp); err != nil {
		return nil, err
	}
	places := map[string]placeEntry{}
	for position, entry := range resp.Places {
		if position == placeLimit {
			break
		}
		places[entry.Bucket] = entry
	}
	return places, nil
}

// refreshPlaces asks every connected peer that speaks PlaceProtocol and
// keeps the answers. A peer that has left keeps its last answer, marked as
// such by its age; one that is no longer a member is forgotten.
func (d *Daemon) refreshPlaces() {
	if !d.begin() {
		return
	}
	defer d.end()
	defer func() {
		d.placeMu.Lock()
		d.placeAsking = false
		d.placeAsked = time.Now()
		d.placeMu.Unlock()
	}()
	now := time.Now()
	for _, peerID := range d.Fabric.Host.Network().Peers() {
		if !d.Fabric.Auth.Allows(peerID, PlaceProtocol) {
			continue
		}
		if protocols, err := d.Fabric.Host.Peerstore().SupportsProtocols(peerID, PlaceProtocol); err != nil || len(protocols) == 0 {
			continue
		}
		places, err := d.askPlaces(peerID)
		if err != nil {
			continue
		}
		answer := peerPlaces{at: time.Now(), places: places}
		if memberCert, ok := d.Fabric.Store.Cert(peerID); ok {
			answer.name = memberCert.Payload.Meta.Name
		}
		d.placeMu.Lock()
		d.peerPlaces[peerID] = answer
		d.placeMu.Unlock()
	}
	d.placeMu.Lock()
	for peerID := range d.peerPlaces {
		if !d.Fabric.Store.IsMember(peerID, now) {
			delete(d.peerPlaces, peerID)
		}
	}
	d.placeMu.Unlock()
}

// peerPlacements is what the peers last said, by bucket. It answers from
// memory and, when that is older than placeMaxAge, starts asking again in
// the background: the listing that calls it is polled and must not wait
// for a slow peer.
func (d *Daemon) peerPlacements() map[string][]PeerPlacement {
	byBucket := map[string][]PeerPlacement{}
	if d.Fabric == nil {
		return byBucket
	}
	d.placeMu.Lock()
	defer d.placeMu.Unlock()
	if !d.placeAsking && time.Since(d.placeAsked) > placeMaxAge {
		d.placeAsking = true
		go d.refreshPlaces()
	}
	for peerID, answer := range d.peerPlaces {
		connected := d.Fabric.Host.Network().Connectedness(peerID) == network.Connected
		for bucketID, entry := range answer.places {
			files := entry.Objects
			if entry.Files != nil {
				files = *entry.Files
			}
			byBucket[bucketID] = append(byBucket[bucketID], PeerPlacement{
				Files:  files,
				PeerID: peerID.String(), Name: answer.name,
				Mode: entry.Mode, Folder: entry.Folder, Keep: entry.Keep,
				Objects: entry.Objects, Held: entry.Held,
				Connected: connected, At: answer.at.UnixNano(),
			})
		}
	}
	for _, placements := range byBucket {
		sort.Slice(placements, func(left, right int) bool {
			if placements[left].Name != placements[right].Name {
				return placements[left].Name < placements[right].Name
			}
			return placements[left].PeerID < placements[right].PeerID
		})
	}
	return byBucket
}
