# Connect two devices

This walkthrough uses two Linux machines that can reach one another, such as
two computers on a LAN. It starts without an IP overlay, root privileges,
or copying the circle's owner key. Both machines need the same current build.

Build on each machine:

```sh
go build -o fabric ./cmd/fabric
```

## 1. Create the circle on the owner device

```sh
./fabric init -name owner -circle demo -subnet ''
./fabric queue on
./fabric up -no-tun -no-vault
```

`init` prompts for an encryption passphrase and creates the first circle and
the device identity. Back up its key containers and the passphrase separately.
The networking daemon uses the device key; owner operations unlock the circle
key in the CLI or UI process.

`queue on` enables the admission lighthouse and makes this node **listed**,
so a new device can contact it. The command name predates Astral queues; it
does not declare an application work queue. Restart `up` after changing it.

Leave `up` running. Note a `listening on .../p2p/<peer-id>` address. If it
starts with `0.0.0.0` or `::`, replace that wildcard with an address reachable
from the other machine, preserving the port and peer ID. For a LAN trial:

```text
/ip4/<owner-lan-address>/tcp/4517/p2p/<owner-peer-id>
```

Allow the chosen port between the machines. The defaults are TCP and UDP
4517. For machines behind separate NATs, see [lighthouses](operations.md#lighthouses-and-nat).

## 2. Create the joining device's identity

On the other machine:

```sh
./fabric join
```

This creates a device key and prints `did:key:...`. It has not joined a
circle yet. Transfer that public DID to the owner and verify it through
a channel you trust.

## 3. Admit that key

In another terminal on the owner, replacing the angle-bracket placeholders:

```sh
./fabric circle admit -circle demo -name worker \
  -gate '<owner-multiaddr-with-peer-id>' -out worker.bundle '<worker-device-did>'
```

This signs a device admission. The bundle contains the admission and a route
to the owner, **not the circle's owner key**. It grants the normal `device`
role for the circle, which includes its data planes; narrowly scoped agent
credentials are a separate step in the [messaging guide](messaging.md).

Move `worker.bundle` privately to the joining machine and run there:

```sh
./fabric join worker.bundle
./fabric up -no-tun -no-vault
```

## 4. Verify the connection

In another terminal on either machine:

```sh
./fabric status
./fabric circle status
```

The peer should become connected and the circle should show a live admission.
Initial gossip and reconnects can take a few seconds. On either machine:

```sh
./fabric ui
```

Open `http://127.0.0.1:4518` locally for the topology, Astral and Vault views.
The UI is a separate process with no login: keep its listener on localhost.
It answers requests addressed to `localhost` or an IP address and refuses any
other host name, so a web page cannot reach it through a name its author
controls. To open it under a name, start it with `-host <name>`.

You can now [host a work queue](messaging.md). To enable Vault, stop `up`
and restart it without `-no-vault`. The daemon uses the existing identity.

## State and command conventions

Defaults follow the XDG directories:

| State | Default |
| --- | --- |
| Device configuration and circles | `~/.config/fabric` |
| Astral journals | `~/.local/share/astral` |
| Vault objects and metadata | `~/.local/share/vault` |

The node's circles live under `<fabric-state>/circles/<name>`. A node can
hold several. The CLI retains first-circle defaults and some `home`/`master`
wording for bootstrap operations; this does not make all held circles one
ownership domain. Specify `-circle` when a command needs a choice.

For an isolated trial, choose explicit paths consistently:

```sh
./fabric init -state /tmp/ioa-owner/node -name owner -circle demo -subnet ''
./fabric queue on -state /tmp/ioa-owner/node
./fabric up -state /tmp/ioa-owner/node -astral-state /tmp/ioa-owner/astral -no-tun -no-vault
# Another terminal:
./fabric status -state /tmp/ioa-owner/node
./fabric astral status -state /tmp/ioa-owner/astral
```

Use fresh directories for a new trial. Most CLI groups require flags before
positional arguments; `fabric bucket` also accepts trailing flags.

`circle export` produces a different kind of bundle: it copies the owner
key and makes its recipient a co-owner. Use `circle admit` for ordinary
devices. Removing a device admission cannot take back a copied owner key.
