# Operating Fabric

Begin with [getting started](getting-started.md). Examples here assume the
default directories; pass explicit state flags when you use other paths.

## Lighthouses and NAT

A listed lighthouse is the reachable contact point for devices behind NAT.
It can accept admission requests and relay authorized peer traffic while
the owner device is offline. Enable the role before starting or restarting:

```sh
./fabric queue on
./fabric up -no-tun
```

Allow TCP and UDP 4517 through the host firewall and the cloud provider's
firewall. Nodes at home can initiate outbound connections. For a cloud
machine behind address translation, declare its public address:

```sh
./fabric announce add gate.example.com
./fabric announce txt
```

Publish the returned `_fabric` TXT record only when you intend DNS-based
discovery. A bootstrap multiaddr pins a peer ID; a TXT record can also pin
the circle. Verify the peer/circle out of band when introducing a new device.

The first-circle queue admission path is also available:

```sh
# Joining device; waits while the owner approves.
./fabric join -name worker gate.example.com
# Owner, another terminal; compare the displayed fingerprint first.
./fabric pending
./fabric approve -no-overlay '<fingerprint-prefix>'
```

Approval for additional named circles through that join queue is unfinished;
use the device-bundle path in [getting started](getting-started.md) for them.
Direct paths are preferred when reachable; relayed connections may later
upgrade through hole punching. Neither path grants resource authority by itself.

## Services and the IP overlay

Linux's optional TUN bridge needs the capabilities to create the interface
and bind the overlay DNS listener. A dedicated machine can use:

```sh
./fabric init -name owner
sudo ./scripts/install-systemd.sh -b "$PWD/fabric"
```

Do initialization only once. The installer copies the build to the selected
service user's `~/.local/bin/fabric`, writes the unit and starts/restarts it.
Use `-u <user>`, `-s <state-dir>` and `-n` for the user, state and no-TUN choices.
Read `scripts/install-systemd.sh -h` before changing an existing installation.

The system service runs in a sandbox. The daemon sees a read-only system and
an empty, read-only home directory, and can write only its state directories,
the folder replicas and placement roots already declared, and directories
named with `-w <dir>`. A flaw in the daemon then reaches Fabric's own data
but not the rest of the account. The installer takes the list from
`fabric up -paths`, which prints what the daemon would use and starts
nothing. To put a folder replica or placement root somewhere new, re-run the
installer with `-w <dir>` first, then declare it.

A sandboxed daemon cannot serve FUSE mounts. The installer refuses a node
that has declared mounts unless it is given `-m`, which installs the service
with no sandbox at all. It also refuses while a state directory is still
waiting for its move out of `~/.config`; run once with `-m`, then again
without.

For a user service on a shared machine:

```sh
./scripts/install-systemd.sh -U -b "$PWD/fabric"
```

It runs without TUN. An IP overlay interface is host-wide, so granting it on
a shared machine would expose a network path to other local processes/users.
The user service is not sandboxed: a user service manager cannot enforce it.

The defaults reserve `100.64.0.0/24` at initial setup. A device admitted with
`-tun` receives a signed overlay address. The current bridge serves one
configured overlay, not every circle's overlay simultaneously.

When using systemd-resolved, the one-time local setup for `.fabric` names is:

```sh
sudo ./fabric dns setup
```

This installs the local authorization needed to configure the bridge's DNS.
Use `./fabric dns off` when that node does not need the resolver integration.

## Renew, remove and restore

Admissions normally last one year. Inspect status and renew before expiry;
there is no unattended owner-key renewal service:

```sh
./fabric status
./fabric renew -expiring
./fabric circle renew -expiring
```

`fabric renew` handles the bootstrap-circle certificates; `circle admit`
reissues an ordinary device's admission in a selected circle. Owner devices
can renew their own circle admissions with `circle renew`.

```sh
./fabric circle revoke -circle demo worker
./fabric circle restore -circle demo -out worker.bundle worker
```

A removal is retained, and admissions must acknowledge known removals.
An ordinary renewal does not undo a removal. `restore` deliberately admits
the device again. Devices learn new state through gossip and reconnects.

Circle key rotation is explicit:

```sh
./fabric circle rotate -circle demo
```

Use `-compromised` for a compromised key; it invalidates the old key's
authority and requires affected devices to be admitted again. Back up the
new key container and follow the command's instructions for other owner devices.
Key rotation is not a way to recover an owner key for which no copy remains.

## Troubleshooting

- **No connection:** inspect `fabric status`, the chosen bootstrap address,
  firewall rules and both processes' logs. A wildcard or loopback address
  is not a reachable address for another machine.
- **Unknown peer refused:** dark nodes expect an existing admission. Use a
  listed contact point and allow time for the new roster entry to propagate.
- **Permission denied:** check the owning circle, credential expiry,
  resource name and verb. Python's `jobs` means `subject:queues/jobs`.
- **Cannot reach a local socket:** use the state directory of the running
  subsystem, not the Fabric device directory. Stop/restart long-running SDK
  clients after a state-directory migration. Python's socket fallback for
  very long state paths is not implemented; prefer short explicit paths.
- **File edits refused:** Vault placement `none` is read-only. Select `full`,
  `cache` or a folder placement first.
- **"Read-only file system" from a bucket command:** the system service is
  sandboxed and the directory is outside what it may write. Re-run the
  installer with `-w <dir>`. The same applies to `bucket project`; the
  daemon's `/tmp` is also private to it.
- **"Runs in a service sandbox and cannot establish mounts":** see the
  services section; mounts need the service installed with `-m`.

For service logs use `journalctl --user -u fabric -f` or the system unit's
`journalctl -u fabric -f`. Keep the web UI local, and inspect logs before
sharing them: addresses, device identifiers and paths may be included.
