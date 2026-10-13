# Native P2P v1

An optional UDP traversal path for the RustDesk Windows/Linux forks. It does not
replace RustDesk's KCP, device identity, login, confirmation or permission logic.
Android/iOS/macOS do not link this crate through `hbb_common`; unsupported peers
continue through the existing rendezvous path.

The implementation follows frp v0.71.0 Modes 1 and 2. See `NOTICE` and `LICENSE.frp` for
the upstream algorithm references and license. No frp executable is used.

## Components

- `protocol`: versioned messages, device/server signatures and sealed probe keys.
- `coordinator`: server capability registry, participant and exit validation,
  per-device request quota and bounded sessions.
- `stun`: two to four IPv4 mapping observations on one retained socket, using
  `stun.easyvoip.com:3478` and its OTHER-ADDRESS/CHANGED-ADDRESS response.
- `hole`: one EasyNAT and one HardNAT, independent of the remote-control direction.
- `strategy`: conservative port prediction and bounded history of TTL/mode outcomes.
- `transport`: signed hbbs RPC, the 45 second deadline and cancellation lease.
- `native-p2p-probe`: the same production protocol/traversal code with a random
  challenge echo instead of the RustDesk remote-desktop session.

Only additive protobuf fields are used: RegisterPeer fields 1000/1001 and the
NativeP2pV1 rendezvous union field 1000. Legacy fields retain their meanings.
The new field contains a bounded, signed JSON envelope, domain separated with
`rustdesk-native-p2p-v1\0`. Version 1 is explicitly negotiated on both devices.

The signed advertisement additionally carries `strategies=1`. Only when both
devices advertise it does hbbs add that field to tickets and a strategy to plans.
Absent fields deserialize to the original fixed Mode 2 path and are omitted
when serializing to older native clients (whose ticket/plan decoders reject
unknown fields). New clients with an old hbbs also use the original two-sample
discovery and Mode 2. The protobuf version and transport label remain v1.

## Adaptive strategies

After the mandatory primary/alternate STUN bindings, enhanced clients try the
two crossed IP/port destinations from the STUN response on the same socket.
Each optional sample is capped at 500 ms, within the existing six-second STUN
budget. Missing optional samples leave the mandatory observations usable.
Public IP changes or a signaling/STUN exit mismatch still fail closed.

Mode 1 is eligible only with at least three distinct destination observations
and a mapped port span of 1..5, following frp's heuristic conservatively. It is
not proof of deterministic allocation. EasyNAT primes at most 21 ports around
the last HardNAT observation, restricted to 1024..65534; HardNAT waits two seconds
and sends at most 20 rounds to EasyNAT's candidates. No extra sockets are opened.
The prediction window is eight seconds. Authenticated replies keep the actual
winning socket, independent of which device initiated remote control.

Mode 2 keeps the proven 256 extra sockets / 1000 distinct random ports / three
second delay / 15 ms spacing. Both modes can prime mappings with TTL 7, TTL 4 or
the OS TTL; the socket TTL is restored before normal transport. Mode 2 retains
its 38-second window. All preparation, probing and KCP share the original
45-second deadline. Each connection selects **one** mode/TTL, as in frp;
failure returns to the original RustDesk connection/relay flow. A later cold
connection can select another strategy, without repeated full punch windows.

The hbbs history holds at most 1024 public network pairs for one hour, including
their Easy/Hard roles and prediction eligibility, never a cached winning port.
Selection costs one point, and a signed caller report after KCP plus the existing
RustDesk device-identity handshake rewards two points (cap 10). The first choice
is prediction/TTL 7 when eligible, otherwise Mode 2/TTL 7. An unsuccessful first
prediction yields to Mode 2/TTL 7 on the next connection; further ties alternate
the modes and TTLs. Scores bottom out at -10 and reset when all eligible choices
are exhausted. Polled plans do not score again. A success report consumes the
attempt, preventing repeated rewards; a responder cannot submit that report.
The diagnostic UDP echo never rewards the history.

After KCP accept, an enhanced receiver leaves cancellation ownership with the
caller until its identity handshake/report completes. Earlier failure still
cancels immediately; server expiry cleans up a crashed caller within 45 seconds.
The caller sends its bounded report asynchronously so reporting cannot turn an
established authenticated transport into a failed connection. No legacy path,
Android hook, KCP implementation, persistent tunnel or dual-HardNAT strategy is
introduced by this extension.

## Authentication and limits

The capability and each request are signed with the registered device Ed25519
key. hbbs validates signatures, nonce freshness/reuse, the device's signaling
exit and membership in the requested session. Tickets and invitations are signed
by the configured hbbs key. A fresh 32-byte probe secret is delivered separately
to both participants with libsodium sealed boxes. Candidate IPv4 addresses must
match that participant's observed signaling exit. Probe messages authenticate
the session, request/response role and a random nonce with libsodium HMAC-SHA512/256.
The normal RustDesk identity handshake still runs after KCP is established.

Begin requests include the configured server public key inside the device-signed
payload. A keyed hbbs rejects a missing or mismatched key before creating a
session or sending an invitation, matching its existing punch admission policy.
Capability withdrawal uses a signed version-0 advertisement; an unsigned legacy
heartbeat cannot revoke a capability. Disabled records keep their bounded replay
history until normal expiry, so replaying a withdrawal after re-enabling fails.

One new attempt per device; at most 64 concurrent sessions and 4096 advertised
devices per coordinator. Each device has 512 signed requests per 60 seconds.
Sessions expire after 45 seconds; capabilities require recent heartbeats. A
cancel removes the session; a peer still punching checks for cancellation once
per second with a one-second RPC timeout. Dropping a local attempt aborts its
socket readers and sends a bounded best-effort cancel RPC. Server expiry covers
crashes or loss of that RPC.

HardNAT uses its retained STUN socket plus 256 additional sockets, sends TTL 7
probes to the EasyNAT candidates, then restores the socket TTL. EasyNAT waits
three seconds and probes up to 1000 distinct ports in 1024..65534, approximately
15 ms apart, using its original socket. Only authenticated replies from the
expected public IPv4 address can win. Loser sockets/tasks are dropped. The
38-second punch window and subsequent KCP setup share the 45-second total budget.

This first version deliberately falls back for two HardNATs, two EasyNATs,
inconsistent exits, failed STUN, IPv6-only paths or unavailable coordination.
An old server's capability wait is at most one second. No background tunnel or
upgrade of an already relayed session is implemented.

## Build and diagnose

From this `hbb_common` checkout:

```text
cargo test --manifest-path native-p2p/Cargo.toml
cargo build --manifest-path native-p2p/Cargo.toml --bin native-p2p-probe
native-p2p-probe discover
native-p2p-probe listen TEST_HOST:22116 TEST_SERVER_PUBLIC_KEY
native-p2p-probe connect TEST_HOST:22116 TEST_SERVER_PUBLIC_KEY LISTENER_ID
```

Start the listener first and use its emitted ID. IDs and private signing keys in
the diagnostic are ephemeral. `verified` proves a bidirectional authenticated
UDP exchange; it does **not** prove a RustDesk login, screen/input operation,
file transfer, KCP stability or a connection-success rate.

Keep TUN enabled during the target-network tests. Process/domain DIRECT rules
must be verified using the observed UDP exit and actual connections; a rule name
alone is not proof of the physical path. No Android-specific TUN rules are needed.

The client and server retain their own `hbb_common` baselines. Apply only this
feature's commits to both branches; do not merge one baseline into the other.
