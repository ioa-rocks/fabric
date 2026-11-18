# Durable work with Astral

Astral runs inside `fabric up`. A queue is identified by its owning circle
and subject name. The CLI currently uses `fabric astral`; Python maps
`queue("jobs")` to `subject:queues/jobs`.

Start with [two connected devices](getting-started.md), or the
[self-contained Python demo](https://github.com/ioa-rocks/fabric-py/tree/main/examples).

## Declare and use a queue

On the node that will hold its journal:

```sh
./fabric astral subject -delivery shared subject:queues/jobs
./fabric astral append -kind request subject:queues/jobs 'hello'
./fabric astral claim -consumer worker subject:queues/jobs
```

Use `shared` for competing workers, `exclusive` for one active consumer.
Only one host declares an ordinary queue. Other nodes find that placement
through the authenticated resource registry. Placement changes are announced
immediately and refreshed periodically (every 10 seconds by default), so a
missed announcement can recover while peers stay connected.

A claim leases an event; acknowledging it removes it from pending work. An
unacknowledged event can be claimed again after the lease expires.

For request/reply:

```sh
# Caller; waits for a worker.
./fabric astral call -kind request subject:queues/jobs 'hello'

# Worker, in another terminal; use the ID from claim.
./fabric astral claim -consumer worker subject:queues/jobs
./fabric astral complete subject:queues/jobs '<request-id>' 'done'
```

`complete` records a signed reply and acknowledges the request in one
journal write. Only the publishing principal collects the reply. The
caller's daemon checks the signature and the signer's current authority.
Plain `ack` of an awaited request ends it with "no reply".

## Give a Python worker a scoped key

On the worker node, issue a key under its device admission:

```sh
./fabric astral key new -res subject:queues/jobs -verbs claim -out worker.key
```

That key can claim and finish work on `jobs`. It cannot publish new jobs or
consume other subjects. Scope and expiry are in the signed statement chain,
checked by the daemon and by the queue's host. The circle's owner key is
not included.

Install the [Python SDK](https://github.com/ioa-rocks/fabric-py) with its
optional signing dependencies, then:

```python
from aethera import Event, Fabric

jobs = Fabric(key="worker.key").queue("jobs")
for claim in jobs.claim(consumer="worker"):
    jobs.complete(claim.event.id, Event(kind="result", source="worker", content="done"))
```

Pass `-fabric-state <dir>` to `astral key` commands when the node uses a
nondefault Fabric directory. Pass `-state <dir>` to queue operations for
a nondefault Astral directory. In Python, use `queue_state=<astral-dir>`.
The key selects its own circle; `-circle` on key issuance takes a circle DID.

Inspect and revoke credentials on the issuing node:

```sh
./fabric astral key list
./fabric astral key revoke '<statement-id-prefix>'
```

Revocation invalidates further operations and active holds as nodes learn
it. An offline node learns the updated circle state when it reconnects.

## Recovery and limits

- Delivery is at least once. Retrying applications should supply a stable
  `Event.id` and make external effects idempotent.
- A Python call can survive its caller's restart: persist the request ID,
  rebuild `queue.call_handle(id)`, read `result()`, and `release()` after
  committing the result locally. The convenience `call()` releases on exit.
- A principal may have 100 requests in flight per host. Release replies
  after incorporating them; a caller that stops waiting does not cancel work.
- Signed sends to an unreachable host are refused. The daemon does not
  park them for later retry as its more powerful device identity.
- A long-lived exchange uses ordinary queues for progress, amendments and
  results; `reply_target` can name a standing result queue. Applications
  retain responsibility for validating and authorizing that return route.
- The Python SDK talks to a local daemon. The CLI additionally supports
  daemon-less grantee workers (`fabric circle grant`, `fabric astral worker`).
- `Fabric(key=...)` does not make a process with operator socket/key access
  untrusted. The deployment owns that process boundary.

## Spread placement

For shared queues, declare the same name with `-spread` on several hosts:

```sh
./fabric astral subject -delivery shared -spread subject:queues/jobs
```

Publishers choose a host and fail over; workers claim across hosts. Each
host keeps an independent journal: an event on a down host waits there,
disk loss loses that host's events, ordering is per host, and ambiguous
publishes can produce duplicates. This is not replicated queue storage.
