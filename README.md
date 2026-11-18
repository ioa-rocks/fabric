# Fabric

**Connect your machines into a private computing environment, with shared
identity and permissions for networking, data, and durable messaging.**

Fabric is the node implementation of **IOA** (formerly Aethera). One Go binary
connects devices, synchronizes selected data, and carries work between tools,
services, and agents. You operate the nodes and choose who may use each resource.

| Part | What it provides |
| --- | --- |
| **Fabric** | Authenticated peer connectivity, NAT traversal, relay fallback, and an optional IP overlay. |
| **Circles** | Ownership domains with device admission, scoped grants, revocation, and key rotation. |
| **Vault** | Content-addressed objects, per-device placement, folder sync, and FUSE mounts. |
| **Astral** | Durable queues, competing workers, claims and acknowledgements, and signed request/reply. |

A device may belong to several circles. Sharing a machine or a connection does
not share every circle's data: resource operations are authorized against the
owning circle. A Python worker can receive permission to consume one queue
without receiving a circle's root key.

## Status

**Pre-alpha, actively developed.** Fabric is used for the author's daily
connectivity and personal storage. This is early software with changing APIs
and wire formats, limited deployment experience, and no independent security
audit. Use disposable data for initial experiments and maintain independent
backups before trying file synchronization.

Linux is the exercised platform; TUN, FUSE and systemd instructions are
Linux-specific. Other platforms are not yet verified. Sources are the current
distribution; installation packages and a stable release channel are future work.

## Start here

- [Connect two devices](docs/getting-started.md) — build, create a circle, and
  admit another device without copying the owner key. Starts without root or TUN.
- [Use durable queues](docs/messaging.md) — declare a queue, delegate work,
  collect signed replies, and issue scoped worker credentials.
- [Try the Python demo](https://github.com/ioa-rocks/fabric-py/tree/main/examples)
  — two local nodes, a scoped worker, and denied operations; no model API required.
- [Store and synchronize data](vault/README.md) — buckets, placements, folders,
  retention, and mounts.
- [Understand the architecture](docs/architecture.md) — identities, trust
  boundaries, and delivery guarantees.
- [Operate nodes](docs/operations.md) — lighthouses, services, renewal, the
  optional IP overlay, and troubleshooting.

## Build

Requires **Go 1.25.7 or newer** (see [go.mod](go.mod)). From this checkout:

```sh
go build -o fabric ./cmd/fabric
./fabric -h
```

The binary contains the networking, circle, bucket, queue, and local web UI
commands. It does not require a hosted control-plane account.

## A small example

With two connected nodes in one circle, the operator hosts a shared queue:

```sh
./fabric astral subject -delivery shared subject:queues/jobs
```

Python code uses the local daemon; the daemon finds the queue's host:

```python
from aethera import Event, Fabric

reply = Fabric().queue("jobs").call(
    Event(kind="request", source="caller", content="hello"), timeout=30
)
print(reply.content, "answered by", reply.signer)
```

A worker on another node claims the request and completes it:

```python
jobs = Fabric(key="worker.key").queue("jobs")
for claim in jobs.claim(consumer="worker"):
    jobs.complete(claim.event.id, Event(kind="result", source="worker", content="done"))
```

The operator issues `worker.key` with `claim` on this queue. See the
[messaging guide](docs/messaging.md) for setup and the
[Python SDK](https://github.com/ioa-rocks/fabric-py) for installation.

## Scope and guarantees

- Circle grants authorize resource operations. Host administrators and processes
  with access to the operator's sockets or keys remain trusted.
- Astral delivery is **at least once**. Applications need stable message IDs
  and idempotent effects; durable queues do not make external effects exactly once.
- A queue has one journal per host. Optional spread placement provides multiple
  independent hosts, not replication of their journals or global ordering.
- Private queue permissions are not end-to-end encryption against their host.
- Vault replicates selected data; synchronized deletion or corruption still
  makes independent backups useful.
- Public discovery, general service streaming, and a distributed execution
  scheduler are not implemented here.

The local UI (`./fabric ui`) shows the topology, queues, and buckets. It binds
to localhost by default and has no login of its own. Keep it local.

## Development

```sh
go test -timeout=10m ./...
go test -race -timeout=10m ./...
make vet
```

Tests use temporary state and loopback nodes. FUSE tests require the relevant
host support and may skip. The privileged TUN test is opt-in; see
[CONTRIBUTING.md](CONTRIBUTING.md). For security reports, see
[SECURITY.md](SECURITY.md).

Licensed under [MPL-2.0](LICENSE).
