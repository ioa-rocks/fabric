# Security

Fabric is pre-alpha and has not had an independent security audit. There is no
supported stable release series yet; use current source and keep communicating
nodes on compatible versions.

For a suspected vulnerability, use GitHub's **Report a vulnerability** feature
if available. If it is unavailable, open an issue asking for a private reporting
channel without publishing exploit details, credentials or affected addresses.
Include the commit, platform, affected component and a synthetic reproduction
when a private channel is established.

The [architecture guide](docs/architecture.md#boundaries-to-understand) describes
the current boundaries. In particular, node administrators, local operator
socket access and stored-key access are trusted. Scoped application credentials
do not sandbox the process holding them. Queue and storage hosts can read their
content, and revocation depends on nodes receiving the updated circle state.

Keep the web UI on localhost. It has administrative signing operations and
no independent login. It refuses requests addressed to a host name it was not
given and requests sent by pages of another origin; it does not authenticate
other programs or users on the same machine. Use disposable state for experiments and redact logs
before sharing them.
