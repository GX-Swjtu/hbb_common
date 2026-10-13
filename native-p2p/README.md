# Native P2P v1

An optional UDP traversal path for the RustDesk Windows/Linux forks. It does not
replace RustDesk's KCP, device identity, login, confirmation or permission logic.
Android/iOS/macOS do not link this crate through `hbb_common`; unsupported peers
continue through the existing rendezvous path.

The implementation follows frp v0.71.0 Mode 2. See `NOTICE` and `LICENSE.frp` for
the upstream algorithm references and license. No frp executable is used.

## Components

- `protocol`: versioned messages, device/server signatures and sealed probe keys.
- `coordinator`: server capability registry, participant and exit validation,
  per-device request quota and bounded sessions.
- `stun`: two IPv4 mapping observations on one retained socket, using
  `stun.easyvoip.com:3478` and its OTHER-ADDRESS/CHANGED-ADDRESS response.
- `hole`: one EasyNAT and one HardNAT, independent of the remote-control direction.
- `transport`: signed hbbs RPC, the 45 second deadline and cancellation lease.
- `native-p2p-probe`: the same production protocol/traversal code with a random
  challenge echo instead of the RustDesk remote-desktop session.

Only additive protobuf fields are used: RegisterPeer fields 1000/1001 and the
NativeP2pV1 rendezvous union field 1000. Legacy fields retain their meanings.
The new field contains a bounded, signed JSON envelope, domain separated with
`rustdesk-native-p2p-v1\0`. Version 1 is explicitly negotiated on both devices.

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
