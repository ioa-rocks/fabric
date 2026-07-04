# fabric

The connectivity layer of [Aethera]: a personal overlay network built on
libp2p, replacing a hand-rolled Nebula deployment with human-gated,
certificate-based membership and a topology/admin UI.

Status: **pre-alpha** — daemon, CLI, the join-then-approve admission
flow, revocation with membership-event gossip, the topology/admin web
UI, and the optional TUN bridge (existing TCP/UDP apps over overlay
IPs) work end-to-end; relay/hole-punching for CGNAT-to-CGNAT paths is
not built yet.

Design documents live in the Aethera project folder
(`components/fabric/` — security-model spec, ADRs, surveys); this repo is
implementation only.

## Build

Requires Go ≥ 1.24.

```sh
go build -o fabric ./cmd/fabric
```

## Quickstart: a two-device mesh

Fabric has no accounts and no cloud: a *namespace* is an ed25519 root
key, membership is a certificate signed by it, and admission is a human
clicking approve. The first device mints the namespace and becomes the
**master** (it holds the root key; keep it on the machine you actually
sit at — it does not need to be always-on or publicly reachable).

**1. On the first device — create the namespace and start the node:**

```sh
fabric init -name work-pc
fabric up
```

`init` asks for a passphrase; the root key is stored encrypted (age,
scrypt) at `<state>/namespace.key.age`. **Back that file up and test the
restore** — losing it means re-keying the mesh. `up` logs the node's
addresses:

```
listening on /ip4/…/tcp/4517/p2p/12D3KooW…
```

**2. On the new device — request admission:**

```sh
fabric join -name nas -bootstrap /ip4/<master-ip>/tcp/4517/p2p/12D3KooW…
```

It prints the device's key fingerprint and polls. Nothing joins without
approval — a leaked bootstrap address only gets an attacker into the
pending queue.

**3. Back on the master — approve:**

```sh
fabric pending                     # shows: <fingerprint>  pending  nas …
fabric approve <fingerprint>       # compare with what the joiner printed!
```

Compare the fingerprint against the joining device's screen before
approving (this is what defeats a man-in-the-middle on the join
channel). Approval prompts for the root-key passphrase and signs a
membership certificate (90-day validity, auto-verified by every peer
offline).

## Lighthouse: taking joins when the master is unreachable

The master (root key, a human at a screen) does not have to be the node
joiners can reach. Designate any always-on, publicly reachable member —
a cloud instance — as the **queue host**:

```sh
fabric queue on     # on that member; restart its daemon to apply
```

Joiners then bootstrap against the lighthouse's address. The pending
queue lives there, but it holds no signing material: `fabric pending`,
`fabric approve`, `fabric deny`, and the web UI on the master
transparently pull the queue over a member- and admin-gated protocol
(`/fabric/queue/1`), sign locally, and send the cert back through the
lighthouse for delivery. This is what makes a CGNAT'd / v6-only master
workable: the master only ever dials out.

Queue restarts are harmless (joiners re-enter by polling). Several
queue hosts can run at once; the master aggregates them.

**4. Start the new node:**

```sh
fabric up        # on the nas
fabric status    # on either device:
#   work-pc          connected member   12D3KooW…
```

Every node prints a `member joined:` line when a new member first
appears — admissions are never silent, by design.

## Kicking a device out

```sh
fabric revoke nas    # on the master; also takes a peer ID or fingerprint
```

Revocation signs a `MemberRevoked` event with the root key (passphrase
prompt, same custody as approval) and gossips it: every member that
hears it drops the peer's live connections and refuses new ones, and
relays the event on to members the master can't reach directly. Nodes
that were offline catch up on their next connect — admissions and
revocations are exchanged peer-to-peer on every connect and persisted,
so a revocation holds even when the master is asleep. Cert expiry
(90 days) remains the backstop for devices the gossip never reaches;
revocation records self-delete once the cert they kill would have
expired anyway. Re-admitting a revoked device means a fresh
`fabric join`.

## The TUN bridge — plain IP over the mesh

Every device gets an overlay address at approval time, signed into its
membership cert (default subnet `100.64.0.0/24`, chosen at `init`).
Nodes that can create a TUN device bridge it to the mesh: Syncthing,
SSH, anything-IP reaches peers at their overlay addresses with no app
changes (deployment mode C, fabric ADRs 0002/0004).

**The bridge is optional per node and needs no root daemon.** Grant
the capability once per binary:

```sh
sudo setcap cap_net_admin+ep $(command -v fabric)   # re-run after rebuilds
fabric up                                           # as your normal user
```

Without the capability (or on non-Linux, or with `-no-tun`), the node
logs a note and runs as a full member over the other modes — it keeps
its overlay address, so TUN-mode peers can still name it consistently
the moment it gains the capability. Traffic is relayed as raw IP
packets on a member-gated stream with source-address pinning; nodes
listen on QUIC (UDP) and TCP, IPv4 and IPv6, so the bridge rides a UDP
underlay whenever both ends support it.

Certs issued before the bridge existed carry no overlay IP — re-join
(or re-init a young namespace) to get addressed.

End-to-end proof without touching real interfaces:
`go build -o fabric ./cmd/fabric && sudo scripts/e2e-tun.sh` — two
network namespaces, a veth pair, ICMP + TCP across the overlay.

## The topology UI

```sh
fabric ui        # → http://127.0.0.1:4518
```

A local web view of the mesh *as this node sees it*: the peer graph
with per-link telemetry (direct vs relayed, transport, who dialed whom,
RTT, the multiaddr that won), membership states (member / pending /
offline / revoked / stranger), this node's NAT reachability verdict
(autonat), cert-expiry warnings, and the membership-event activity
feed. On the master it is also the admin surface: approve/deny pending
joins (with the fingerprint displayed for comparison) and revoke
members.

`fabric ui` is deliberately a separate process from the daemon: the
root-key passphrase is entered in the browser form, but signing happens
inside the `fabric ui` process on the master — the daemon never sees
key or passphrase, same custody model as the CLI. On a non-master node
the UI is a read-only mesh view. It binds to localhost and has no auth
of its own; don't point `-listen` at a routable interface.

## Commands

| Command | Where | What |
|---|---|---|
| `fabric init -name <label>` | first device | mint the namespace, become master |
| `fabric up` | any member | run the node daemon |
| `fabric status` | any member | node, membership, and connection state |
| `fabric join -name <label> -bootstrap <addr>` | new device | request admission and wait |
| `fabric pending` | master | list join requests |
| `fabric approve <fingerprint>` | master | sign a membership cert for a pending request |
| `fabric deny <fingerprint>` | master | reject a pending request |
| `fabric revoke <name \| peer-id \| fingerprint>` | master | revoke a member and gossip the cut-off |
| `fabric ui [-listen 127.0.0.1:4518]` | any member | serve the topology/admin web UI |
| `fabric queue on\|off` | any member | run the admission queue (lighthouse role) |
| `fabric peer add <multiaddr>` | any member | add a bootstrap peer |

All commands take `-state <dir>` (default `~/.config/fabric`), so
several nodes can run on one machine for testing. Flags go **before**
positional arguments (`fabric approve -state DIR FP`). Set
`FABRIC_PASSPHRASE` to skip the interactive passphrase prompt (CI,
scripts).

## Packages

- `cert` — membership certificates: minimal ed25519-signed
  deterministic-CBOR structs whose fields mirror the UCAN 1.0 delegation
  payload (`iss`/`aud`/`sub`/`cmd`/`nbf`/`exp`/`prf`), so a future
  migration to real UCANs changes serialization, not the data model.
  `did:key` codec included (it's 30 lines; no DID library).
- `keystore` — the namespace root seed at rest: an age-encrypted file
  (passphrase / scrypt). The seed exists in memory only during a signing
  session — approval happens in the CLI process; the daemon never holds
  the root key.
- `event` — signed membership events (`MemberAdded` / `MemberRevoked`)
  and the deduplicating, expiry-GC'd event log they accumulate in: the
  durable membership view every node carries.
- `fabricnet` — membership enforcement on a libp2p host, layered:
  a connection gater (hard-denies revoked peers, admits strangers only
  long enough to authenticate), the `/fabric/auth/1` mutual certificate
  handshake, per-protocol member checks (`RequireMember`), revocation
  that closes live connections, and `/fabric/events/1` gossip — full-log
  anti-entropy on every connect plus rumor-mill relay of fresh events.
  First-contact join notifications (admission transparency) surface
  through `JoinObserver`.
- `admission` — the `/fabric/join/1` protocol and the pending queue
  (holds no signing material; certs are handed to it only for delivery).
- `daemon` — the node process: host wiring, bootstrap reconnect/reauth
  loop, event-log persistence/replay, link telemetry (member-gated ping
  RTT, autonat reachability), control API over a unix socket for the
  CLI and UI.
- `webui` — the topology/admin UI: an embedded no-build-step web app
  (`fabric ui`) that reads through the control socket and signs
  approvals/revocations in its own process, never the daemon's.
- `tunbridge` — deployment mode C: overlay-address allocation, the
  kernel TUN device (Linux, in-process netlink so a file capability
  suffices), and the L3 packet relay over `/fabric/tun/1` — no
  userspace TCP/IP stack; both ends' kernels terminate TCP (ADR 0004).
- `state` — the state directory: config, device key, own cert,
  keystore path, control socket.

## Development

```sh
go test ./...        # includes multi-host integration tests over loopback
go test -race ./...
```

An end-to-end verification recipe (two live daemons, full admission
flow) is in `.claude/skills/verify/SKILL.md`.

License: MPL-2.0.

[Aethera]: ../../  <!-- vision docs; not yet published -->
