# Contributing

Fabric is an early project. Small reproducible problems, documentation fixes,
and focused patches are useful contributions. For a larger protocol or API
change, start a GitHub issue describing the workload it should enable.

Read the [architecture guide](docs/architecture.md) and the guide for the
component you are changing. Keep connectivity, authority, storage, messaging
and application execution responsibilities separate.

From a checkout with Go 1.25.7 or newer:

```sh
make fmt-check
go vet ./...
go test -timeout=10m ./...
```

For changes to concurrency, leases or storage, also run the relevant packages
under `go test -race`. Tests use temporary state and loopback listeners; they
need permission to open sockets. FUSE checks may skip when the host cannot mount.

The optional `scripts/e2e-tun.sh` test needs root and creates network namespaces
and virtual interfaces. Read it before running it on a disposable Linux host.
Ordinary tests and the Python demo do not require TUN or root.

Use names that explain a value's role. Keep changes focused, describe the
observable behavior and validation in the pull request, and add regression
coverage when fixing a substantive failure. Protocol changes must state their
mixed-version behavior and any state migration.

Do not include live keys, credentials, machine state, deployment logs, private
customer discussions or real infrastructure addresses in patches. Use temporary
state, synthetic identities and `example.com`/`example.org` in examples.

Contributions are provided under the repository's [MPL-2.0 license](LICENSE).
See [SECURITY.md](SECURITY.md) for vulnerability reporting.
