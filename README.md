# fabric

The node implementation of [Aethera]: a personal overlay network built
on libp2p — human-gated, certificate-based membership with a
topology/admin UI — plus, on devices that opt in, **Vault**, the
synchronized personal object store, as a subsystem of the same daemon
(one process, one device identity per machine; ADR 0013). See
[`vault/README.md`](vault/README.md) for the data layer; the rest of
this README is the connectivity layer.

Status: **pre-alpha** — daemon, CLI, the join-then-approve admission
flow, revocation with membership-event gossip, the topology/admin web
UI, the optional TUN bridge (existing TCP/UDP apps over overlay IPs),
self-forming mesh (address gossip), and NAT traversal (members-only
relay through lighthouses + hole-punching) work end-to-end. Vault:
buckets/objects/tags, catalog+index anti-entropy, subscription-driven
blob transfer over member-gated protocols.

Design documents live in the Aethera project folder
(`components/fabric/` and `components/vault/` — security-model spec,
bucket-model memo, ADRs, surveys); this repo is implementation only.

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
restore** — losing it means re-keying the mesh. The same key is minted as
the node's *home circle* (`-circle`, default `home`): the namespace DID is
the circle DID, and a device's membership cert is also its attestation
into that circle, so buckets and queues of the home circle need no extra
`circle attest`. `up` logs the node's addresses:

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
transparently pull the queue over a members-only protocol that answers the master's device alone
(`/fabric/queue/1`), sign locally, and send the cert back through the
lighthouse for delivery. This is what makes a CGNAT'd / v6-only master
workable: the master only ever dials out.

Queue restarts are harmless (joiners re-enter by polling). Several
queue hosts can run at once; the master aggregates them.

**Posture: dark vs listed.** Every node is *dark* by default: an
inbound connection from a peer ID it holds no current cert for is
refused right after the transport handshake, before multistream,
identify or the auth protocol run. Members are learned by gossip from
the lighthouses first, so a freshly admitted member may be refused by a
dark node for one reconnect tick until its `MemberAdded` event arrives;
`fabric status` shows the posture and a count of refused unknown
inbound connections. A queue host is *listed* (strangers must reach it
to join); `"listed": true` in `config.json` lists any other node that
has to accept unknown peers. Outbound dials are never gated by
posture: the node chose them, and the handshake settles who answered.
One exemption: an unknown inbound peer arriving from the IP of a
connected member that this node trusts as NAT oracle is admitted,
because libp2p's AutoNAT dials back from a throwaway identity on the
lighthouse's machine; the grace watchdog still closes it unless it
authenticates. Oracles are decided locally: the lighthouses in the
node's configured `bootstrap` list (the join target, `fabric peer
add`), never a member merely advertising the dial protocol, and not the
lighthouses pinned from discovery (`discovered_bootstrap`, dialed for
recovery only). Ordinary members do not earn the exemption: a phone on
carrier NAT would otherwise open the dark node to everyone sharing its
address.

**4. Start the new node:**

```sh
fabric up        # on the nas
fabric status    # on either device:
#   work-pc          connected member   12D3KooW…
```

Every node prints a `member joined:` line when a new member first
appears — admissions are never silent, by design.

## End to end: home + cloud, no inbound ports at home

The full runbook from nothing to a mesh spanning a NAT'd home and
public cloud nodes. Key property: home machines only ever dial *out* —
no router firewall holes, no DDNS, no stable-address fights. The one
place that *does* need an open port is the lighthouse (step 4): the
mesh needs a single publicly dialable anchor, and cloud instances sit
behind their provider's firewall until told otherwise.

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
directions. Learned records are **persisted** (`records.cbor`), so a
restarted node redials its peers from the cache instead of waiting to
be told where everyone is again — the mesh reforms even when the node
you originally joined through is down. `fabric peer add` remains
useful for pinning a lighthouse, not for wiring up every pair.

**4. Promote the cloud node to lighthouse.** Three things make a
working lighthouse: the queue role, an open port, and an announced
public address.

```sh
# on cloud-a:
fabric queue on    # restart the daemon to apply
```

**Open the fabric port** in the provider's firewall (AWS security
group, GCP firewall rule, …): **UDP 4517** (QUIC, the preferred
transport) and **TCP 4517** (fallback), source anywhere. Home members
still need nothing opened — they dial out to the lighthouse, and
NAT'd pairs meet through it (step 6).

**Announce the public address.** A cloud instance's public IP is 1:1
NAT at the provider's edge — it is never on an interface inside the
VM, so the daemon cannot discover it and would otherwise advertise
only private addresses (if your nodes also share a VPN, the mesh will
quietly ride *that* instead — every path a node advertises is raced):

```sh
fabric announce add gate.example.com
# (a bare IP works too; DNS survives re-IPs. Full multiaddrs remain
#  accepted as an escape hatch for unusual ports/transports.)
```

The command verifies the name before saving it: it dials the derived
addresses expecting this node's own identity. A name that verifiably
points at a *different* machine is refused (`-force` overrides) — a
wrong record would gossip to every member. Mere silence (daemon not
started yet, firewall still closed, hairpin-refusing NAT) only warns.

One name is all it takes: the daemon derives ports and transports
from its listen config, resolves the name into IP-literal addresses
(and keeps re-resolving while it runs, so dynamic DNS just works),
and advertises both forms. The literals matter: libp2p's autonat
client only uses peers with a public IP literal as NAT oracles — a
DNS-only record would leave the whole mesh at "NAT: unknown". An
announcing queue host also asserts public reachability outright
(`ForceReachabilityPublic`), which starts its relay service
immediately instead of waiting for another oracle to confirm what
the operator already knows.

The announced addresses join the node's signed address record and
reach every member over the normal gossip — no per-node `peer add`
needed once this is set.

**5. Every further node — join via the lighthouse**, no tunnels, no
master reachability needed:

```sh
fabric join -name cloud-b -bootstrap /ip4/<cloud-a-ip>/udp/4517/quic-v1/p2p/<cloud-a-peer-id>
```

Or skip the multiaddr entirely: publish the DNS record that `fabric
announce txt` prints on the lighthouse —

```
_fabric.gate.example.com. 300 IN TXT "v=fabric1; peer=<peer-id>; ns=<namespace-did>"
```

— and every future device joins with just:

```sh
fabric join -name laptop gate.example.com
```

The TXT record supplies the peer-ID pin, and its `ns=` entry pre-pins
the namespace: the join hard-fails if the queue host serves a
different one. Without `ns=` (or when joining by multiaddr), the
joiner prints the namespace DID it is about to trust — compare it with
the master's UI header in the same glance that compares the joiner's
fingerprint. Both checks exist because DNS alone is spoofable: a
hijacked name must not be able to usher your device into an impostor
namespace.

The request waits in cloud-a's queue; `fabric pending` / the UI on the
master shows it (pulled remotely over the queue protocol, which answers only the master's device),
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

While a peer remains relayed, Fabric keeps trying to upgrade it every two
minutes, and sooner when a fresh signed address record arrives. The side
that accepted the relayed connection re-runs the DCUtR hole punch: both ends
dial each other at the same instant, which is what two stateful firewalls
(a home router, a mobile carrier) need to admit a UDP flow. libp2p's own
service punches only once, right after the relayed connection is made, and a
punch attempted while a laptop's uplink is flapping stays failed; Fabric
therefore owns the service and drives it from mesh-fill. The side that dialed
the relay cannot initiate a punch (the protocol rejects that direction) and
falls back to a plain direct dial, which helps only when the peer has a real
pinhole. Both kinds of attempt keep the relay open, share the recovery dial
limits, and stop once a direct connection exists. Punch attempts are logged
as `holepunch:` lines. libp2p's global UDP/IPv6 failure suppression is
disabled: repeated failures to an offline device must not block working
transports to other members or survive a laptop's change of network. Per-peer
dial backoff remains enabled.

### Sleep, wake, and address changes

The daemon checks underlay interface addresses every 15 seconds and uses a
wall-clock gap of 45 seconds to detect likely suspend/resume. These signals
close old transports and clear dial backoff. Thirty seconds with no connected
members also clears backoff, then retries that reset at most once a minute.
Bootstrap addresses are grouped by peer; up to eight peers dial concurrently,
with ten-second attempt deadlines. Recovery and dial failures appear in the
service journal, with repeated failures limited to once per peer per minute.
Autorelay can reserve through the first eligible lighthouse: candidate checks
are spaced five seconds apart, with a 15-second reservation backoff and a
ten-second boot fallback. This avoids libp2p's default wait for four candidates
and three-minute boot fallback in a mesh with only two lighthouses.

Each device publishes its own signed address record when libp2p observes an
address or relay-reservation change. Records carry an increasing, timestamp-based
sequence number belonging to that device. Connected members spread new versions;
reconnecting to a lighthouse exchanges the latest records it holds for other
members too. Newer records remove withdrawn endpoints and trigger a fresh dial
to disconnected peers. Equal versions refresh cached addresses without starting
a gossip loop; older versions cannot roll back the in-memory version watermark.

Overlay delivery needs a connection to the destination, either direct or through
a valid circuit-relay reservation. A graph path through an arbitrary member does
not provide IP forwarding. TUN stream opens and writes have five-second deadlines
so a stale stream cannot stall packet handling indefinitely. A real sleep/wake
trial is still needed to verify recovery timing on each host and network.

## Renewing certificates

Certs live a year and renew at half-life (spec §5) — renewal re-signs
the *same* payload (name, role, overlay IP; nothing renumbers) with a
fresh validity window, so it needs the master:

```sh
fabric renew nas          # one member (also: peer ID / fingerprint)
fabric renew -expiring    # everything past half-life, this node included
fabric renew -scope vault guest-pc   # change a member's protocol scope (promotion/demotion is a renewal;
                                     # adding tun assigns an overlay address, dropping it releases one)
fabric renew -ip 100.64.0.2 nas      # renumber: move a member to a free overlay address (then restart
                                     # its daemon so fabric0 re-addresses; routes and .fabric names follow
                                     # the cert on every other node without a restart)
```

or the "Renew cert" button on any peer (and on the master's own card)
in the web UI. The re-signed cert travels as a regular MemberAdded
event on the existing gossip: every store keeps the later-expiring
cert regardless of arrival order, and the renewed node adopts its new
cert live — persisted and presented in handshakes immediately, no
restart. Renewals log as `cert renewed`, not as a new member joining,
so the admission-transparency alarm stays meaningful. Expiry is loud
before it bites: anything expired or expiring within 30 days raises a
red banner across the top of every node's UI (with a "Renew now" button
on the master) and a `!!! CERTIFICATES NEED ATTENTION` block at the top
of `fabric status`; 30–90 days shows a softer banner and the node card's
"renew soon" badge.

Renew *before* expiry: an expired node can't connect to receive its
renewal (the mesh refuses it before gossip could reach it), and its
path back is a fresh `fabric join` on that device — same device key, so
it keeps its name and its overlay address. Until then it stays on the
roster as **expired** (`fabric status`: `EXPIRED`; UI: "expired —
re-join needed") rather than vanishing: an expired device that connects
is shown by name instead of as an anonymous stranger, an offline one is
still listed, its address stays reserved, and `renew` refuses it with a
pointer to `join`. That memory lasts a year past expiry
(`cert.LapsedRetention`); revoking the device ("Forget device" in the
UI) ends it early. Renewal is also how members admitted before the TUN
bridge (certs without an overlay IP) get re-issued — though they
currently keep their empty IP; assigning one at renewal is a small
follow-up.

To re-join an expired device that still has its state directory: stop
the daemon, move `config.json` and `cert.cbor` aside, run `fabric join
-name <its name> -bootstrap <a queue host>`, approve on the master, put
the old `config.json` back (same namespace; it carries `queue_host`,
`announce_addrs`, bootstrap pins) and start the daemon.

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

### Circle attestations: the same lifecycle, one layer up

A device's *circle attestation* (what makes peers of a circle sync with
it) lives one year like a cert and renews by re-signing on a device
that holds the circle key:

```sh
fabric circle attest -expiring            # renew every attestation past half-life
fabric circle revoke her-pc -circle family # an owner device signs a device out
```

Revocation is a circle-signed record kept beside the circle
(`circles/<name>/revocations.cbor`). Devices of the circle swap their
revocation sets on every circle exchange (`/fabric/circle/3`), and the
daemon on the revoking node pushes the new one to every member connected
right now, so the revoked device drops out of that circle's sync at
once wherever the news reaches, and at the next connect elsewhere.
Expiry is the backstop. A revocation kills the device's attestations
issued up to that moment; attesting the device again afterwards is a
deliberate re-admission and stands. `fabric status` warns loudly about
expired, expiring and revoked attestations, as it does for certs.
Attestations minted before 2026-10-31 carry no window and count as
valid for one year from issue; nodes older than that verify newer
attestations but enforce neither expiry nor revocation until upgraded.

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
nothing to re-bless. `-b/-u/-s` select the source build, user, and state dir;
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

The service installer copies the selected build atomically to the service user's
`~/.local/bin/fabric` and writes that canonical path into `ExecStart`. Re-running
it reloads and restarts the service. To migrate a dedicated host from `~/fabric`
or a repository build, run the installer with the existing user and state path:

```sh
sudo ./scripts/install-systemd.sh -u "$USER" -b "$HOME/fabric" -s "$HOME/.config/fabric"
```

Use the actual service user/state directory if they differ, and retain `-n` if
TUN was explicitly disabled. The source build and identity/state files remain
in place. User services use `-U` instead of sudo and `-u`.

## Deploy to existing nodes

For the current x86-64 Ubuntu fleet, the binary can deploy itself over SSH:

```sh
fabric deploy kodi
fabric deploy kodi gate.example.com relay.example.org
```

It installs atomically at `~/.local/bin/fabric`, migrates the supported legacy
`~/fabric` service path via a compatibility symlink to that binary, restarts the existing system or user
unit, and waits for `fabric status` to pass. Run it from the freshly built
binary you intend to distribute. Release artifacts and mixed-architecture
fleets remain future deployment work.

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
members. Its Astral card shows hosted and remotely placed names, backlog,
active claim leases, heartbeat monitors, the offline outbox, and the current
authorization boundary. Vault lists buckets with their owning circles. Each
bucket links to `/buckets/<id>`, a bookmarkable detail page with overview,
local placement and folder/mount status, conflicts and held-deletion counts,
and paginated files. Placement controls live on that page. Folder replicas
show their existing placement without offering a blob-store mode switch.
The file view browses at most 100 objects per page in stable object-ID order,
with Previous/Next and an explicit Refresh that returns to the first page.
Dashboard polling preserves the open page and does not reload its objects.
The dedicated `/objects/page` control endpoint
seeks by cursor and scans at most 1,000 records per request; a page containing
only deleted or filtered records can be empty with a Next cursor. Pages are
independent reads, so refresh to see insertions before the current cursor.
Deploy the daemon along with the UI for this endpoint; the CLI
and SDK complete-list endpoint remains unchanged.

`fabric ui` is deliberately a separate process from the daemon: the
root-key passphrase is entered in the browser form, but signing happens
inside the `fabric ui` process on the master — the daemon never sees
key or passphrase, same custody model as the CLI. On a non-master node
the UI is a read-only mesh view. It binds to localhost and has no auth
of its own; don't point `-listen` at a routable interface.

## Astral: hosted pub/sub queues

`fabric up` also runs Astral, the durable pub/sub journal used by tools and
agents. One internal subject model supports exclusive inboxes and shared
worker queues through explicit delivery policy, plus offline delivery, claim
leases and acknowledgements, wait/timer wake, and heartbeat monitors. The local API is a
mode-0600 Unix socket; `fabric astral` exposes the same verbs for development
and inspection.

**Subjects belong to circles.** A subject is `(circle DID, name)`
(overlapping-circles memo §12.4, §17): two circles may both have a
`subject:jobs`, and a node hosting for several keeps them apart. Every
`fabric astral` command takes `-circle <did>`; without it a name is in this
node's *home circle* (the namespace DID), which is also what a journal
written before this change migrates into on first start.

Subject placement is discovered between authenticated Fabric members. A node
announces the refs it hosts on connect and whenever it declares another one;
peers atomically refresh placements (keyed by peer ID) and remove stale
refs. Conflicts are per ref: a ref another node already holds is refused
and logged, the rest of the announcement lands. `fabric astral host` remains
as a manual/debug override, not normal mesh configuration. The stream
protocol is `/astral/subject/2` (framed, circle on the wire); v1 is still
served and dialed for one release, with bare names meaning the home circle.

**Every verb is checked against the caller's chain.** The host asks the
circle service whether the connection peer may do the verb on that
`(circle, name)`: its device attestation in that circle (from the circle
exchange), or its membership cert for the home circle, checked on every
call for window, scope, honoured roots and revocations (overlapping-circles
memo §17: honoured *up to the verbs on the device assert*). `append` needs
`publish`; `claim`, `wait` and `heartbeat` need `claim`; `ack` needs `ack`
unless the caller acks its own live lease; `get`/`watch` need `read`;
registers follow their entity's subject; a registry announcement is kept
only for refs the announcer may `host`. A member outside the circle is
refused, not parked. Pre-statement certs and attestations carry no verbs
and count as the full device set. Consumer-name strings are still not
authorization.

**Sub-keys.** An agent or worker on a device gets a key of its own, chained
under the device's assert in one circle and narrowed to named subjects and
verbs:

```sh
fabric astral key new -circle did:key:z6Mk…team -res subject:jobs -verbs claim -exp 720h -out worker.key
fabric astral claim subject:jobs -key worker.key -consumer w1 -wait 30
fabric astral key list
fabric astral key revoke 3f9a2c1e        # reaches members online now; the rest on their next exchange
```

The daemon signs with the hot device key (member certs are `del 1`, the
sub-key is `del 0`), keeps a record per key, and never keeps the seed —
the key file is the only copy. A call made with `-key` is signed by the
sub-key over the operation (op, circle, name, event id, consumer, value,
time) and carries its chain; the host, local or remote, verifies the
signature and checks the chain for the verb, so a claim-only key cannot
publish even on its own node. Leases and sources name the key
(`<consumer>@<key8>@<member>`). Foreign grantees present their chain the
same way (next slices, `tasks/open/astral-per-circle.md`).

**Revocation reaches live state at once.** Every lease, watch and parked
wait records who holds it (connection peer, and the chain for a sub-key).
When a revocation lands — or a device is forgotten — the host re-checks
each holder: a lease whose authority died is released so another worker
reclaims the job immediately, its watches are dropped, and its parked
waits return a revocation error. The same re-check runs on a timer for
chains that merely expire. Leases and heartbeat TTLs are capped at ten
minutes, and a wait ends when its stream does.

**Request and reply.** `fabric astral append <queue> -reply …` asks the
host of the queue for a reply slot: the host allocates
`subject:queues/_reply/<request-id>` in its own circle, owned by itself,
readable only by the principal that published the request, and points the
request at it. The worker that holds the request's live lease is the only
one who may append to the slot, with a reply signed over the request it
answers (`-corr <request-id>`; the device key signs for a device, the
sub-key for a `-key` caller), so a host can drop a reply but neither forge
nor replay one. Slots are never announced; the requester's node routes to
the host it published through, the worker's to the host it claimed from.
A slot idles out after ten minutes and a late reply is refused loudly, not
parked. Quota: 100 live slots per principal per host.

```sh
fabric astral subject subject:queues/agents/concierge/inbox -delivery exclusive -accepts user,system
fabric astral append subject:queues/agents/concierge/inbox -kind user "translate this"
fabric astral claim subject:queues/agents/concierge/inbox -consumer concierge -wait 30
fabric astral status
fabric astral subject subject:jobs -circle did:key:z6Mk…team -delivery shared   # a team-circle queue
```

`subject:` is currently implementation vocabulary. The resource UX is
`fabric bucket|queue|service`, one noun each (fabric ADR 0006); buckets
already follow it. Exposing top-level `fabric queue` first requires renaming
the existing admission `queue on|off` command.

The same operator state is visible in `fabric ui`; use `-astral-state` when
the UI and daemon use a non-default Astral state directory.

## Commands

| Command | Where | What |
|---|---|---|
| `fabric init -name <label> [-circle <name>]` | first device | mint the namespace, become master; the root key is also the home circle (default `home`) |
| `fabric root status` | any member | current root, roots still honoured during a move, members that have not yet *presented* a cert under the new root in a handshake with this daemon (the log alone only proves the cert was issued) |
| `fabric root merge -circle <name>` | master | move the namespace onto a circle's key: re-issues every cert under it, publishes `root-moved` (signed by the old root), installs the circle key as the root container; the old root stays honoured. Idempotent: if it fails part-way, rerun it and it resumes (re-issues only missing certs, installs the key only if still pending) |
| `fabric root retire [-force] <did>` | master | publish `root-retired` (signed by the new root): the old root stops verifying everywhere; refuses while a live member has not presented a new-root cert to this daemon unless `-force` (those members are cut off and must re-join) |
| `fabric up` | any member | run the node daemon (serves buckets when the node has a circle; `-no-vault` / `-vault-state <dir>`) |
| `fabric status` | any member | node, membership, and connection state |
| `fabric graph [-json]` | any member | whole-mesh link map, human or machine readable |
| `fabric join -name <label> <host \| -bootstrap <addr>>` | new device | request admission and wait; bare hostname resolves via its `_fabric` TXT record |
| `fabric pending` | master | list join requests |
| `fabric approve [-scope tun,vault,astral\|mesh] [-no-overlay] <fingerprint>` | master | sign a membership cert for a pending request. `-scope` signs a protocol scope into the cert: the control plane plus only the listed families (`mesh` = connectivity only); `-no-overlay` = everything but TUN. Every node enforces it in both directions, so the member cannot opt back in (semi-trusted hardware; fabric ADR 0005) |
| `fabric deny <fingerprint>` | master | reject a pending request |
| `fabric revoke <name \| peer-id \| fingerprint>` | master | revoke a member and gossip the cut-off |
| `fabric ui [-listen 127.0.0.1:4518]` | any member | serve the topology/admin web UI |
| `fabric queue on\|off` | any member | run the admission queue (lighthouse role) |
| `fabric peer add <multiaddr>` | any member | add a bootstrap peer |
| `fabric announce add <hostname\|ip\|multiaddr>` | cloud/1:1-NAT nodes | also advertise an address no local interface carries; ports, transports, and resolved IPs derived automatically |
| `fabric announce txt` | lighthouse | print the DNS TXT record enabling hostname joins |
| `fabric circle init -name <name>` | any device | mint a circle — a user key that buckets (and next, subjects) belong to. A node holds any number of circles under `<state>/circles/<name>`: the owner's personal one, a shared `family` one, … |
| `fabric circle attest [-expiring]` | each device of a circle | sign this device into the circle (done automatically by `circle init`/`join` when the node already has a fabric identity), or renew: attestations live one year like certs; `-expiring` re-signs every one past half-life. Peers sync buckets and serve blobs only to attested devices of their own circle — mesh membership alone no longer grants vault access |
| `fabric circle revoke [-circle <name>] <member \| did:key>` | an owner device of the circle | sign a device out of the circle; devices of the circle learn it on their next circle exchange, the running daemon pushes it to those connected now (see *Circle attestations*) |
| `fabric circle export [-circle <name>] <file>` / `fabric circle join <file>` | another device | carry a circle to another device, which then holds its key and is attested into it (interim until sub-key grants). A shared circle is how two people share buckets: both devices hold it, neither holds the other's personal circle |
| `fabric circle passphrase [-circle <name>]` | each device holding the circle | re-encrypt the circle's key container under a new passphrase. The key does not change, so nothing is re-signed or re-sent; when the circle is the mesh root (after `root merge`) the root key container is rewritten with it. Other devices holding the circle keep the old passphrase until the same is run there (or they re-join from a fresh `export`). There is no recovery for a forgotten passphrase: back up the container (`circles/<name>/user.key.age`) and the passphrase off the device |
| `fabric circle status` | any member | circles held, this device's role and attestation (expiry, revoked), revocations held, buckets per circle, mounts, folders, mesh, and which circles each vault peer verifiably shares |
| `fabric bucket ...` | any member | the circle's buckets: `create`, `list`, `place <b> full\|cache\|none\|folder <dir>`, `mount`, `put/ls/get/rm/…` (`fabric bucket -h`; a `vault` symlink means the same) |
| `fabric astral ...` | any member | inspect and use the coordination plane (`fabric astral -h`) |

All commands take `-state <dir>` (default `~/.config/fabric`; for the
`bucket` group it is the store, default `~/.config/vault`, with
`-circle-state` for the circle), so several nodes can run on one machine
for testing. Flags go **before** positional arguments (`fabric approve
-state DIR FP`; the bucket group also accepts them after). Set
`FABRIC_PASSPHRASE` (namespace root key) and `CIRCLE_PASSPHRASE` (circle
user key) to skip the interactive prompts (CI, scripts).

## Packages

- `statement` — the one signed statement and the one verifier
  (`tasks/open/statement-format.md`): UCAN-ordered payload (`iss`/`aud`/
  `sub`/`res`/`verbs`/`del`/`meta`/`prf`), `{payload bytes, sig}` on the
  wire, id = sha256(payload). `Compile` does signatures, chaining,
  attenuation, delegation depth, overlay metadata and admission authority
  once per chain; `Compiled.Check` is the cheap per-verb step (presenter,
  window, scope, revocations by statement-ID ancestry). Attestations,
  grants, sub-keys and revocations are instances, not types.
- `did` — the `did:key` codec for ed25519 keys (30 lines; no DID library),
  shared by `cert`, `circle` and `statement`.
- `cert` — membership certificates as statements: the device assert
  {member (+admin) (+tun) + scope verbs, name, ip}. `Payload` stays the
  view every caller reads; certs minted before 2026-11-02 still decode,
  verify and renew into statements.
- `keystore` — the namespace root seed at rest: an age-encrypted file
  (passphrase / scrypt). The seed exists in memory only during a signing
  session — approval happens in the CLI process; the daemon never holds
  the root key.
- `event` — signed membership events (`MemberAdded` / `MemberRevoked`,
  plus `root-moved` / `root-retired` for the mesh-root merge) and the
  deduplicating, expiry-GC'd event log they accumulate in: the durable
  membership view every node carries. Verified against the node's
  honoured roots (`namespace_did` + `honoured_roots` in config).
- `fabricnet` — membership enforcement on a libp2p host, layered:
  a connection gater (hard-denies revoked peers; dark by default, so a
  node refuses inbound peers outside its member store before any
  protocol runs, and listed on lighthouses so joiners and not-yet-gossiped
  members can authenticate), the `/fabric/auth/1` mutual certificate
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
- `circle` — the ownership layer (ADR 0017): the owner's user key
  (age container, same keystore discipline as the root key), its DID,
  and the export/join bundle. Below vault and astral; `fabric circle`
  manages it. A node holds any number of circles (`<state>/circles/<name>`).
- `vault/…` — the data layer: `bucket`, `blobstore`, `index`, `store`
  (the device's store, opened against a circle), `folder`, and the
  vault subsystem daemon; `fabric bucket` is its CLI. See
  [`vault/README.md`](vault/README.md).

## Development

```sh
go test ./...        # includes multi-host integration tests over loopback
go test -race ./...
```

An end-to-end verification recipe (two live daemons, full admission
flow) is in `.claude/skills/verify/SKILL.md`.

License: MPL-2.0.

[Aethera]: ../../  <!-- vision docs; not yet published -->
