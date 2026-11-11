package daemon_test

import (
	"testing"
	"time"

	"ioa.rocks/fabric/vault/daemon"
)

// Each device's bucket listing says how the other holds the bucket: the
// holder sees the reader's cache and its budget, the reader sees the holder
// in full, and a change of placement shows up on the other side.
func TestListingShowsPlacementOnPeers(t *testing.T) {
	t.Cleanup(daemon.SetPlaceMaxAge(100 * time.Millisecond))
	pair := newBlobPair(t)
	pair.cacheWithBudget(t, 5<<20)
	pair.put(t, "film.mkv", film(1<<20))

	seenBy := func(client *daemon.Client) (daemon.PeerPlacement, bool) {
		buckets, err := client.Buckets()
		if err != nil || len(buckets) != 1 || len(buckets[0].Peers) != 1 {
			return daemon.PeerPlacement{}, false
		}
		return buckets[0].Peers[0], true
	}
	waitFor(t, "the holder to see the reader's cache and budget", func() bool {
		placement, ok := seenBy(pair.holderClient)
		return ok && placement.Mode == "cache" && placement.Keep == 5<<20 && placement.Objects == 1 && placement.Held == 0 &&
			placement.Connected && placement.PeerID == pair.reader.Fabric.Host.ID().String()
	})
	waitFor(t, "the reader to see the holder in full", func() bool {
		placement, ok := seenBy(pair.readerClient)
		return ok && placement.Mode == "full" && placement.Held == 1 && placement.Name != ""
	})
	if err := pair.readerClient.Place("films", "none", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the holder to see the reader unplaced", func() bool {
		placement, ok := seenBy(pair.holderClient)
		return ok && placement.Mode == "" && placement.Keep == 0
	})
}
