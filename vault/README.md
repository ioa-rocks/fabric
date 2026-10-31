# vault

An API-first, content-addressed object store for a personal mesh —
the data layer of the Aethera stack. Apps talk to Vault through its
API; sync happens at the object level; the filesystem is one
*surface* (read-only projections now, FUSE later), never the
substrate. Rides [fabric](../fabric) in library mode for membership
and transport.

Spec: `components/vault/memos/bucket-model.md` in the project docs.
Design anchors: ADR 0009 (build the semantics, adopt the
primitives), ADR 0010 (user keys + capability tokens), ADR 0011
(buckets live in circles; policy inherits).

## Model in one breath

A **circle** is a user key plus policy defaults. A **bucket** is a
signed genesis record (its BLAKE3 hash is the bucket ID) plus a
policy document, an **index** (object metadata: LWW scalars,
OR-Set tags, tombstones — and blob location records), and
**blobs** (whole-file, BLAKE3-addressed, immutable). Placement is
subscription-based: each device declares `full`, `shard(group)`, or
`cache` per bucket; bucket health = number of complete copies.
Hierarchy is a rendered view; tags are the navigation truth
(faceted addressing).

## v2 API surface (sketch — evolves with its three consumers)

The three consumers the API is sketched against: the CLI importer,
the projection writer, and the shared-album read path.

```
Circle:    fabric-level `circle` package — Init(name) / Open(dir) / Unlock
Store:     Open(dir, circle) — blobs, bucket records, placement (this package tree)
Buckets:   Create(name) -> Bucket, List(), Open(id|name)
Objects:   Put(bucket, name, reader, tags...) -> Object
           Get(bucket, objectID) -> reader
           List(bucket, tagFilter...) -> []Object     // faceted query
           Tag(bucket, objectID, +tag/-tag)
           Delete(bucket, objectID)                    // tombstone
Surfaces:  Project(bucket, dir)                        // read-only materialization
Later:     Subscribe(bucket, mode), Grant(bucket, userKey, caps),
           serve layer (gallery / URL shares), FUSE
```

## Build

The fabric binary carries the CLI (ADR 0013 — one binary). Ownership is
`fabric circle …` (the user key; a fabric-level package, ADR 0017), data is
`fabric bucket …` — one noun per group, consumed once (fabric ADR 0006). A
`vault → fabric` symlink means `fabric bucket` (argv[0] dispatch,
busybox-style); `cmd/vault` builds the same group standalone.

```sh
go build -o fabric ./cmd/fabric && ln -s fabric vault
go test ./...
```

Quickstart (throwaway directories; `-state` is the fabric state dir for
circle commands and the store dir for bucket commands):

```sh
export CIRCLE_PASSPHRASE=test         # or omit for an interactive prompt
./fabric circle init -state /tmp/f -name alex
./fabric bucket create -state /tmp/v -circle-state /tmp/f/circle family-photos
./fabric bucket put -state /tmp/v -circle-state /tmp/f/circle -tag pets,2026 family-photos cat.jpg
./fabric bucket ls  -state /tmp/v -circle-state /tmp/f/circle -tag pets family-photos
./fabric bucket project -state /tmp/v -circle-state /tmp/f/circle family-photos /tmp/album
```

Defaults: circle `~/.config/fabric/circle`, store `~/.config/vault`. With a
daemon running, bucket commands never need `-circle-state` (the daemon
holds the circle); without one, the direct path opens it. Flags may come
before or after positional arguments (after `tag`'s `<bucket>
<object-ref>`, `-x` means "remove tag x").

## Daemon & mesh

Vault is a **subsystem of the node daemon** (ADR 0013 — one process,
one device identity per machine). `fabric up` activates it when the
node has a circle (`<state>/circle`; the store defaults to
`~/.config/vault`, override with `-vault-state`; `-no-vault` to skip)
and is pure connectivity otherwise. A circle still living in the store
directory from before the hoist is adopted automatically at startup
(the two files are copied; the originals stay, unused). The subsystem
serves the object API over a local control socket
(`<vault-state>/control.sock`, HTTP+JSON — the seed of the
network-facing API). While the daemon runs it owns the store (Pebble
locks); the bucket CLI detects the socket and routes through it —
same commands, same output. With no daemon running, the CLI opens
the store directly.

Mesh membership is the machine's, managed by the fabric CLI:

```sh
fabric join -name desk /ip4/…/tcp/4517/p2p/12D3Koo…   # approve on the master
fabric circle init -name alex   # create the circle (once, on one device); a node may hold several
fabric up &                     # node daemon; vault subsystem activates
fabric circle status            # circle, buckets served, mesh, vault peers
```

"Which devices run vault" is simply which members have vault state —
participation is opt-in per device (memo §5). Vault peers find each
other among mesh members by the `/vault/hello/1` protocol
(member-gated; carries circle DID + version) — but they **sync and serve
blobs only to verified devices of their own circle**: each device holds
a *device attestation* signed by the circle key (`circle init`/`join`
mint it; `fabric circle attest` for a device that joined earlier), and
peers check it on `/fabric/circle/3` after membership auth. A mesh
member outside the circle sees the hello card and nothing else.
Attestations live one year and renew by re-signing (`fabric circle
attest -expiring`); an owner device signs one out with `fabric circle
revoke`, and the revocation travels on the same exchange (fabric
README, *Circle attestations*).
Mesh-level debugging: `fabric status`; `fabric circle status` shows
whether this device is attested and which peers verify as same-circle.

**A second device of the same owner** (interim procedure until
capability grants let a device hold a sub-key — `circle init` there
would mint a *different* user key): export the circle, join with it,
then restart the daemon so the subsystem activates.

```sh
fabric circle export -circle alex alex.circle   # carries the key container (passphrase-protected)
scp alex.circle other:                    # move it privately
ssh other 'fabric circle join alex.circle && rm alex.circle && systemctl --user restart fabric'
#   join asks for the circle passphrase and attests the device (needs the fabric
#   identity — if the node has not joined the mesh yet, run 'fabric circle attest' after it has)
# on other:
fabric bucket list                        # catalog arrives via sync (≤30 s after connect)
```

**Sharing with another person** is a second circle, not a grant: mint it,
join their device to it, and mint the shared buckets in it. Each device
syncs exactly the buckets of the circles it is attested into — the
personal circle's buckets never reach the other person, not even their
catalog entries.

```sh
fabric circle init -name family                 # on the desk: now holds "main" and "family"
fabric circle export -circle family family.circle
# their device: fabric circle join family.circle   (joins family only; attests itself)
fabric bucket create album -circle family       # owned by the shared circle
fabric bucket list                              # shows the owner circle per bucket
fabric bucket place <bucket> full         # and blobs follow
```

Only the circle travels — `blobs/`, `buckets/`, `subs.json`,
`mounts.json` and `folders.json` are per-device state that sync owns.

## Sync & placement

Anti-entropy on `/vault/sync/1` (fabric spec-§5 pattern): a full
catalog + index swap on every connect, on a 30 s timer, and pushed
after local writes — the CRDT merge (LWW / OR-Set / tombstones) makes
repetition and reordering harmless. Unknown buckets are adopted after
signature verification. Blobs move separately on `/vault/blob/1`,
driven by subscriptions (memo §5 — pull, not push):

```sh
fabric bucket place photos full          # hold a complete copy; fetch what's missing
fabric bucket place photos cache         # hold what gets accessed (no eviction yet)
fabric bucket place photos none          # catalog + index only
fabric bucket place photos folder ~/Sync # keep it as a real directory (a full placement)
fabric bucket place photos full -at /mnt/array/vault  # keep its blobs on that disk
fabric bucket place photos full -at default           # back to <state>/blobs
fabric bucket place photos               # this device's placement, in detail
fabric bucket list                       # id, placement word, held/objects, name, where
```

Placement is one word per bucket per device; moving off `folder`
withdraws the folder declaration and leaves the directory alone. `-at
<dir>` gives a `full`/`cache` placement its own blob store root (a NAS
keeps the photo bucket on the array and small buckets on NVMe); the
root is this device's business and never travels. Blobs already in the
default store stay there and stay readable — nothing is moved; a root
that cannot be opened refuses writes rather than landing them on the
wrong disk. Per-device placement records live in `subs.json`
(`{"mode": "full", "root": "/mnt/array/vault"}`; the older bare-mode
form still reads).
Mounts (`fabric bucket mount <bucket> <dir> [-write]`) are a surface over
the store, not a placement. The creating device places `full` by
default. `fabric bucket get` works
on *any* vault node that can reach a holder — a missing blob is a
mesh lookup, not an error. Transfers are verified by re-hashing
(content addressing is the integrity check). Trust boundary today:
any authenticated mesh member may sync and fetch; per-circle
visibility and capability checks arrive with grants.

## Layout

- `bucket/` — genesis record, bucket ID, policy document
- `blobstore/` — content-addressed whole-file blob store
- `index/` — object records + merge semantics (LWW / OR-Set), Pebble-backed
- `store/` — the device's store: bucket records, blobs, placements
  (mode + optional store root), mounts, folder declarations, bucket handles; opened against a circle
  (`../circle` — user key, age-encrypted via fabric's keystore; the
  ownership layer, fabric-level since 2026-09-30)
- `folder/` — folder replicas (M1): scanner, materializer, shadow store
- `daemon/` — the vault subsystem: control API (HTTP over unix
  socket), sync/blob/hello protocols; attached to the fabric daemon
  by `cmd/fabric up` (the composition root)
- `cli/` — the `fabric bucket` group (daemon client when one is
  running, direct otherwise); `../cmd/vault` builds it standalone

## Status

Bootstrapped 2026-07-05. Local object-store core, daemon, and sync
(same day): create circle + bucket, put/tag/list/get objects, project
a bucket to a directory; mesh presence via the fabric daemon;
catalog/index anti-entropy +
subscription-driven blob movement verified end-to-end (two-node tests:
on-demand get, full-sub proactive fetch, concurrent tag merge,
tombstone propagation — race-detector clean). 2026-07-07: one-process
topology per ADR 0013, then the repo merge — vault moved into the
fabric repo as `vault/` packages; `fabric up` hosts the subsystem,
`vault join/up` deleted (mesh membership is `fabric join`), the
`vault` binary is the data CLI only. 2026-09-30: the circle hoisted to
the fabric level (`circle` package; `vault/circle` → `vault/store`) and
the CLI regrammared to `fabric circle …` + `fabric bucket …` (fabric
ADR 0006).
Next: live two-machine rollout (desk + NAS), then capability grants
(second user key) and
the projection consumer. Deferred: cache eviction (LRU), drop-safety
verify-before-drop, shard groups, health targets, delta sync. The
years-old Python prototype lives at `../../vault_proto_py`
(parts-bin).
