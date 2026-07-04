# fabric

The connectivity layer of [Aethera]: a personal overlay network built on
libp2p, replacing a hand-rolled Nebula deployment with human-gated,
certificate-based membership and a topology/admin UI.

Status: **pre-alpha** — the membership core exists (certificates, key
custody, connection-level enforcement); daemon, admission queue, TUN
bridge, and UI are not built yet.

Design documents live in the Aethera project folder
(`components/fabric/` — security-model spec, ADRs, surveys); this repo is
implementation only.

## Packages

- `cert` — membership certificates: minimal ed25519-signed
  deterministic-CBOR structs whose fields mirror the UCAN 1.0 delegation
  payload (`iss`/`aud`/`sub`/`cmd`/`nbf`/`exp`/`prf`), so a future
  migration to real UCANs changes serialization, not the data model.
  `did:key` codec included (it's 30 lines; no DID library).
- `keystore` — the namespace root seed at rest: an age-encrypted file
  (passphrase / scrypt). The seed exists in memory only during a signing
  session.
- `fabricnet` — membership enforcement on a libp2p host, layered:
  a connection gater (hard-denies revoked peers, admits strangers only
  long enough to authenticate), the `/fabric/auth/1` mutual certificate
  handshake, per-protocol member checks (`RequireMember`), and
  revocation that closes live connections. First-contact join
  notifications (admission transparency) surface through `JoinObserver`.

## Development

```
go test ./...        # includes multi-host integration tests over loopback
go test -race ./...
```

License: MPL-2.0.

[Aethera]: ../../  <!-- vision docs; not yet published -->
