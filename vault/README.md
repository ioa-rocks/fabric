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
Circle:    Init(name) / Open(statedir)
Buckets:   Create(name) -> Bucket, List(), Open(id|name)
Objects:   Put(bucket, name, reader, tags...) -> Object
           Get(bucket, objectID) -> reader
           List(bucket, tagFilter...) -> []Object     // faceted query
           Tag(bucket, objectID, +tag/-tag)
           Delete(bucket, objectID)                    // tombstone
Surfaces:  Project(bucket, dir)                        // read-only materialization
           Mount(bucket, dir)                          // read-only FUSE view
Later:     Subscribe(bucket, mode), Grant(bucket, userKey, caps),
           serve layer (gallery / URL shares), writable/faceted FUSE
```

## Build

The fabric binary carries the data CLI (ADR 0013 — one binary): run it
as `fabric vault …`, or symlink `vault → fabric` for the plain `vault …`
spelling — argv[0] dispatch, busybox-style. `cmd/vault` still builds the
same commands standalone for a data-CLI-only install:

```sh
go build -o fabric ./cmd/fabric && ln -s fabric vault
go test ./...
```

Quickstart (throwaway state dir):

```sh
export VAULT_PASSPHRASE=test          # or omit for an interactive prompt
./vault init -state /tmp/v -name alex
./vault bucket create -state /tmp/v family-photos
./vault put -state /tmp/v -tag pets,2026 family-photos cat.jpg
./vault ls  -state /tmp/v -tag pets family-photos
./vault project -state /tmp/v family-photos /tmp/album   # read-only view
# with `fabric up` running:
./vault mount -state /tmp/v family-photos /tmp/album-live
```

Default state dir is `~/.config/vault`; every command accepts
`-state`. Flags may come before or after positional arguments
(after `tag`'s `<bucket> <object-ref>`, `-x` means "remove tag x").

## Daemon & mesh

Vault is a **subsystem of the node daemon** (ADR 0013 — one process,
one device identity per machine). `fabric up` activates it when
circle state exists (default `~/.config/vault`, override with
`-vault-state`; `-no-vault` to skip) and is pure connectivity
otherwise. The subsystem serves the object API over a local control
socket (`<vault-state>/control.sock`, HTTP+JSON — the seed of the
network-facing API). While the daemon runs it owns the store (Pebble
locks); the `vault` CLI detects the socket and routes through it —
same commands, same output. With no daemon running, the CLI opens
the state directly.

Mesh membership is the machine's, managed by the fabric CLI:

```sh
fabric join -name desk /ip4/…/tcp/4517/p2p/12D3Koo…   # approve on the master
vault init -name alex     # create the circle (once, any device)
fabric up &               # node daemon; vault subsystem activates
vault status              # circle, mesh membership, connected vault peers
```

"Which devices run vault" is simply which members have vault state —
participation is opt-in per device (memo §5). Vault peers find each
other among mesh members by the `/vault/hello/1` protocol
(member-gated; carries circle DID + version). Mesh-level debugging:
`fabric status`.

**A second device of the same owner** (interim procedure until
capability grants land — `vault init` would mint a *different* user
key): copy the circle identity, then restart the daemon so the
subsystem activates.

```sh
ssh other 'mkdir -p -m 700 ~/.config/vault'
scp ~/.config/vault/config.json ~/.config/vault/user.key.age other:.config/vault/
# on other: restart 'fabric up' (systemctl restart fabric), then
vault buckets            # catalog arrives via sync (≤30 s after connect)
vault sub <bucket> full  # and blobs follow
```

Only those two files — `blobs/`, `buckets/`, and `subs.json` are
per-device state that sync owns. The key container keeps its
passphrase.

## Sync & placement

Anti-entropy on `/vault/sync/1` (fabric spec-§5 pattern): a full
catalog + index swap on every connect, on a 30 s timer, and pushed
after local writes — the CRDT merge (LWW / OR-Set / tombstones) makes
repetition and reordering harmless. Unknown buckets are adopted after
signature verification. Blobs move separately on `/vault/blob/1`,
driven by subscriptions (memo §5 — pull, not push):

```sh
vault sub photos full    # hold a complete copy; fetch what's missing
vault sub photos cache   # hold what gets accessed (no eviction yet)
vault sub photos none    # catalog + index only
vault buckets            # id, sub mode, held/objects, name
```

The creating device subscribes `full` by default. `vault get` works
on *any* vault node that can reach a holder — a missing blob is a
mesh lookup, not an error. Transfers are verified by re-hashing
(content addressing is the integrity check). Trust boundary today:
any authenticated mesh member may sync and fetch; per-circle
visibility and capability checks arrive with grants.

## Read-only FUSE mount

`vault mount <bucket> <dir>` is the practical access surface for dogfooding
and legacy consumers. Stored object names appear as ordinary paths; opening a
file reads through the daemon, so `cache`/`none` can fetch a missing blob from
a connected holder. The mount rejects writes.

This first cut snapshots names when mounted; remount to see added, renamed, or
deleted objects. Content is fetched live on every open. Objects imported by an
older binary may report zero size and should be re-imported for filesystem
consumers. Duplicate names gain an `~<object-id>` suffix. Requires Linux FUSE
and a running `fabric up` daemon.

## Layout

- `bucket/` — genesis record, bucket ID, policy document
- `blobstore/` — content-addressed whole-file blob store
- `index/` — object records + merge semantics (LWW / OR-Set), Pebble-backed
- `circle/` — user key (age-encrypted via fabric's keystore), state dir
- `daemon/` — the vault subsystem: control API (HTTP over unix
  socket), sync/blob/hello protocols; attached to the fabric daemon
  by `cmd/fabric up` (the composition root)
- `../cmd/vault` — data CLI (daemon client when one is running,
  direct otherwise)

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
`vault` binary is the data CLI only.
Next: live two-machine rollout (desk + NAS), then capability grants
(second user key) and
the projection consumer. Deferred: cache eviction (LRU), drop-safety
verify-before-drop, shard groups, health targets, delta sync. The
years-old Python prototype lives at `../../vault_proto_py`
(parts-bin).
