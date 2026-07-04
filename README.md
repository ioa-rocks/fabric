# fabric

The connectivity layer of [Aethera]: a personal overlay network built on
libp2p, replacing a hand-rolled Nebula deployment with human-gated,
certificate-based membership and a topology/admin UI.

Status: **pre-alpha** — daemon, CLI, and the join-then-approve admission
flow work end-to-end; revocation CLI, membership-event gossip, the
topology UI, and the TUN bridge are not built yet.

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

**4. Start the new node:**

```sh
fabric up        # on the nas
fabric status    # on either device:
#   work-pc          connected member   12D3KooW…
```

Every node prints a `member joined:` line when a new member first
appears — admissions are never silent, by design.

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
- `fabricnet` — membership enforcement on a libp2p host, layered:
  a connection gater (hard-denies revoked peers, admits strangers only
  long enough to authenticate), the `/fabric/auth/1` mutual certificate
  handshake, per-protocol member checks (`RequireMember`), and
  revocation that closes live connections. First-contact join
  notifications (admission transparency) surface through `JoinObserver`.
- `admission` — the `/fabric/join/1` protocol and the pending queue
  (holds no signing material; certs are handed to it only for delivery).
- `daemon` — the node process: host wiring, bootstrap reconnect/reauth
  loop, control API over a unix socket for the CLI and the future UI.
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
