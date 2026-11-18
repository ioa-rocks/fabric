# Vault

Vault is Fabric's content-addressed data layer. It synchronizes bucket metadata
and selected content between authorized devices of the owning circle. Folder
replicas and FUSE mounts expose that data as files; applications can also use
the local API directly.

Start with [two connected devices](../docs/getting-started.md), then run
`fabric up` without `-no-vault` on both. The existing circle admissions
provide resource authority; no owner-key export is needed on the second device.

## Create and read a bucket

On the owner device, with the daemon running:

```sh
./fabric bucket create -circle demo photos
./fabric bucket put photos cat.jpg -tag pets
./fabric bucket ls photos -tag pets
./fabric bucket get photos '<object-ref>' -o cat-copy.jpg
```

Creating a bucket signs its genesis and policy, so it requires the circle's
owner key. The CLI prompts for the passphrase; the daemon does not receive
it. The creating device initially places the bucket in full.

The catalog becomes visible to admitted devices with the appropriate bucket
authority. On the other device:

```sh
./fabric bucket list
./fabric bucket place photos full
```

Allow a connect/gossip cycle for metadata to arrive. Use a bucket ID when
names are ambiguous. Synchronization checks `sync`, merging records checks
`write`, and serving content checks `blob` on the bucket in its owning circle.
The general cross-circle grantee synchronization path is unfinished.

## Choose where content lives

| Placement | Behavior |
| --- | --- |
| `full` | Fetch and retain a complete copy. |
| `cache` | Retain accessed content; an optional budget evicts older reads. |
| `none` | Keep metadata and permit on-demand reads; refuse local edits. Reads can retain bytes. |
| `folder <dir>` | Maintain a synchronized real directory; a complete placement. |

```sh
./fabric bucket place photos cache -keep 20G
./fabric bucket place photos full -at /mnt/storage/vault
./fabric bucket place photos folder ~/Pictures/Shared
./fabric bucket place photos
```

Use a fresh directory for an initial folder experiment. The daemon owns
scanning, synchronization and filesystem materialization. Changing placement
away from `folder` leaves the directory in place. `-at` is device-local; it
selects the blob-store root without moving existing blobs.

A budgeted cache evicts least-recently-read content only after a full holder
confirms it has that blob. This is a confirmation from that holder, not a
cryptographic proof of durable storage.

## Mount and inspect

On Linux with FUSE available:

```sh
./fabric bucket mount photos /path/to/mount
./fabric bucket mount photos /path/to/writable-mount -write
./fabric bucket unmount /path/to/mount
```

Mount declarations are served by the node daemon, including across restarts.
Writable mounts require a writable placement (`full` or `cache`). The local
web UI lists buckets, placements, files, conflicts and held deletions.

## Retention and repair

```sh
./fabric bucket trash photos
./fabric bucket restore photos '<object-ref>'
./fabric bucket versions photos '<object-ref>'
./fabric bucket revert photos '<object-ref>' '<version>'
./fabric bucket conflicts photos
./fabric bucket reclaim -dry-run
./fabric bucket scrub photos
```

Deletion is a synchronized tombstone. Deleted content is restorable while
retained under `trash_days`; overwritten content is kept under `version_days`
(by default following trash retention). A device records versions it sees
replaced; the editing folder device may need another holder to retain the old
bytes. Policy, conflict and held-deletion commands are described by
`./fabric bucket -h`.

Reclaim removes content no bucket on that device retains. Scrub reads held
content, detects damage, and attempts repair from a full peer. These mechanisms
do not replace an independent backup.

## Storage and transfer

The default store is `~/.local/share/vault` (`$XDG_DATA_HOME/vault` when set).
The node's circles are in `~/.config/fabric/circles/<name>`; the old singular
`circle/` layout is not the current format. Override the daemon store with
`-vault-state`; the bucket CLI's `-state` refers to that same store.

While a daemon owns the store, the CLI uses its local socket. With no daemon,
the CLI can open the store directly using `-circle-state <circles-root>`.
Do not copy a live database as a synchronization mechanism.

Content is immutable and addressed by BLAKE3. `/vault/blob/3` transfers verified,
resumable byte ranges; the older whole-blob transfer remains for compatibility.
Metadata merges use per-field LWW and OR-Set rules, with retained conflicts and
tombstones. Content synchronization is not a globally ordered transaction log.

`bucket`, `blobstore`, `index`, `store`, `folder`, `fusefs`, `verified`,
`daemon`, and `cli` contain the implementation. Sharded placement, delta sync
and a stable public wire protocol are future work.
