# fabric

The connectivity layer of [Aethera]: a personal overlay network built on
libp2p, replacing a hand-rolled Nebula deployment with human-gated,
certificate-based membership and a topology/admin UI.

Status: **pre-alpha** — daemon, CLI, the join-then-approve admission
flow, revocation with membership-event gossip, the topology/admin web
UI, the optional TUN bridge (existing TCP/UDP apps over overlay IPs),
self-forming mesh (address gossip), and NAT traversal (members-only
relay through lighthouses + hole-punching) work end-to-end.

Design documents live in the Aethera project folder
(`components/fabric/` — security-model spec, ADRs, surveys); this repo is
implementation only.

## Build

Requires Go ≥ 1.25.

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

A queue host is the full lighthouse: admission queue, members-only
circuit relay, and the autonat service that tells NAT'd members they
are private. Joiners bootstrap against the lighthouse's address. The pending
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

## End to end: home + cloud, no inbound ports anywhere

The full runbook from nothing to a mesh spanning a NAT'd home and
public cloud nodes. Key property: home machines only ever dial *out* —
no router firewall holes, no DDNS, no stable-address fights.

**1. Master (the machine you sit at):**

```sh
go build -o fabric ./cmd/fabric
sudo setcap 'cap_net_admin,cap_net_bind_service+ep' ./fabric
./fabric init -name desk
sudo ./fabric dns setup        # once; resolver self-registers from now on
./fabric up &                  # logs: tun up, dns serving + registered
./fabric ui &                  # http://127.0.0.1:4518
```

**2. LAN devices** join directly against the master's LAN address
(quickstart above): `fabric join -name nas -bootstrap
/ip4/<master-lan-ip>/tcp/4517/p2p/<master-peer-id>`, approve in the UI
or CLI, `fabric up`. The name given at join is the device's `.fabric`
name — `ssh nas.fabric` afterwards.

**3. First cloud node — join through an SSH reverse tunnel.** The
cloud can't dial into a CGNAT'd/v6-rotating home, and it doesn't need
to: carry the join through the SSH session you already have.

```sh
# on the master:
ssh -R 14517:localhost:4517 you@cloud-a

# on cloud-a, through that tunnel:
fabric join -name cloud-a -bootstrap /ip4/127.0.0.1/tcp/14517/p2p/<master-peer-id>

# approve on the master (fingerprint comparison as always), then on cloud-a:
fabric up
```

The tunnel is only for admission. From there the mesh forms itself:
every member gossips a **self-signed address record** (its current
dialable multiaddrs, sequence-numbered) on the same anti-entropy
channel as membership events, and every daemon opportunistically dials
members it knows addresses for but isn't connected to. libp2p races
all known addresses, so the best real path wins — LAN beats WAN,
whichever side *can* dial does, and one connection carries both
directions. `fabric peer add` remains useful for pinning a lighthouse,
not for wiring up every pair.

**4. Promote the cloud node to lighthouse.** On `cloud-a`:

```sh
fabric queue on    # restart the daemon to apply
```

**5. Every further node — join via the lighthouse**, no tunnels, no
master reachability needed:

```sh
fabric join -name cloud-b -bootstrap /ip4/<cloud-a-ip>/udp/4517/quic-v1/p2p/<cloud-a-peer-id>
```

The request waits in cloud-a's queue; `fabric pending` / the UI on the
master shows it (pulled remotely over the admin-gated queue protocol),
approval signs on the master and delivers through the lighthouse. The
master can be asleep when joiners knock — they wait in the queue.

**6. NAT'd pairs that can't dial each other** (laptop in a café ↔ NAS
at home) go **through the lighthouse**: queue hosts also run a
members-only circuit-relay-v2 service (unlimited — it's your own
hardware) and the autonat dial-back service. A node that learns it is
NAT-private reserves a relay slot, its `/p2p-circuit` address rides
the normal gossiped address record, and peers dial it through the
relay — shown dashed with "relay" in the UI. Hole-punching (DCUtR)
then tries to upgrade every relayed connection to a direct one; when
it succeeds the edge turns solid, when it fails the relay keeps
carrying the traffic, TUN included. A revoked member loses relay
privileges with the same gossip that cuts its connections.

## Renewing certificates

Certs live a year and renew at half-life (spec §5) — renewal re-signs
the *same* payload (name, role, overlay IP; nothing renumbers) with a
fresh validity window, so it needs the master:

```sh
fabric renew nas          # one member (also: peer ID / fingerprint)
fabric renew -expiring    # everything past half-life, this node included
```

or the "Renew cert" button on any peer (and on the master's own card)
in the web UI. The re-signed cert travels as a regular MemberAdded
event on the existing gossip: every store keeps the later-expiring
cert regardless of arrival order, and the renewed node adopts its new
cert live — persisted and presented in handshakes immediately, no
restart. Renewals log as `cert renewed`, not as a new member joining,
so the admission-transparency alarm stays meaningful. The UI flags
certs under 90 days ("renew soon") and under 30 ("renew NOW").

Renew *before* expiry: an expired node can't connect to receive its
renewal (the mesh refuses it), and its path back is a fresh `fabric
join`. Renewal is also how members admitted before the TUN bridge
(certs without an overlay IP) get re-issued — though they currently
keep their empty IP; assigning one at renewal is a small follow-up.

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
(one year, renewed at half-life) remains the backstop for devices the
gossip never reaches;
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
the capabilities once per binary (`net_admin` for the TUN device,
`net_bind_service` for the `.fabric` DNS on port 53):

```sh
sudo setcap 'cap_net_admin,cap_net_bind_service+ep' $(command -v fabric)   # re-run after rebuilds
fabric up                                                                  # as your normal user
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

## Run it as a service

For anything past experiments, run the daemon under systemd so it
survives reboots and crashes. Pick the mode by **trust boundary**, not
by whether you happen to have root:

```sh
sudo ./scripts/install-systemd.sh          # dedicated machines (after init/join)
./scripts/install-systemd.sh -U            # shared machines (no root needed)
```

**System service** (machines that are yours alone — desktop, NAS,
your cloud instances): starts at boot, runs `fabric up` as your
normal user; the TUN and port-53 capabilities are granted by systemd
(`AmbientCapabilities`) rather than setcap on the binary, so upgrades
are just "replace the binary, `sudo systemctl restart fabric`" —
nothing to re-bless. `-b/-u/-s` override binary, user, and state dir;
`-n` disables TUN. Logs: `journalctl -u fabric -f`.

**User service** (`-U`, machines other people also use — a shared
server, a work box): installs to `~/.config/systemd/user/` with zero
root footprint and runs while you're logged in (`loginctl
enable-linger` keeps it up across logouts, where allowed). No TUN or
`.fabric` DNS here — and that's the *point*, not a limitation: a TUN
device is host-wide, so bridging the overlay on a shared machine
would hand every user and process on that box an IP route into your
private network. The node is a full member on the control plane
(gossip, admission, even lighthouse duty) and carries your traffic
once the per-user userspace proxy (mode B) lands, which is scoped to
your processes instead of the whole host. For the same reason, don't
"fix" a shared machine by setcap'ing the binary — that works
mechanically, but it bridges your overlay to everyone on the box.

The web UI is deliberately *not* a service: `fabric ui` holds the
namespace root key (signs approvals, revocations, renewals) and should
only run interactively on the master, unlocked when you need it —
that's the cold-key custody model, not an oversight.

**Names: `ssh nas.fabric`.** When the bridge is up, the daemon serves
`<member>.fabric` on its own overlay address — the member store is the
zone, straight from the signed certs; nothing to configure and nothing
that survives revocation. To make the OS use it, point a routing
domain at the resolver (the daemon tries this itself and prints the
command if it lacks the rights):

```sh
sudo resolvectl dns fabric0 <your-overlay-ip>
sudo resolvectl domain fabric0 '~fabric'
```

The daemon attempts this itself over D-Bus with interactive
authorization disabled — it never pops an auth dialog or hangs a tty,
but as a plain user it will be refused until you run, once per
machine:

```sh
sudo fabric dns setup
```

That installs a polkit rule (`/etc/polkit-1/rules.d/50-fabric-dns.rules`)
allowing your user's daemon to set resolved's DNS/domain for its own
link — from then on names configure themselves on every daemon start,
reboots included — and registers immediately if `fabric0` is already
up. On nodes that don't need names at all (cloud boxes you only ssh
*to*), `fabric dns off`.

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
| `fabric graph [-json]` | any member | whole-mesh link map, human or machine readable |
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
- `fabricdns` — the `.fabric` resolver: authoritative for
  `<member>.fabric` from the member store, bound to the node's overlay
  address while the bridge is up.
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
