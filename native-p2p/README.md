# Native UDP punching

An optional traversal path for the RustDesk Windows/Linux forks. It retains
RustDesk's KCP, device identity, login, confirmation and permission checks.
The Android client uses the same default-on strategy option, with optional LAN
candidates supplied to `Session::punch_on`; iOS/macOS keep the original connection flow.
The algorithms are adapted from frp v0.71.0
(`4a23aa181c1d7e28eecaa8216024ed753b9d27c8`); see `NOTICE` and `LICENSE.frp`.
No frp executable is required.

## One capability

The only signed feature declaration is `capability="native-udp-punch"` with an
`enabled` boolean. Both devices and the coordinator must support this exact
capability before a session is issued. There are no strategy generation flags
or separate V2 switch. `enable-native-p2p=N` disables the entire native attempt.
Finite callers fall back for unsupported peers; graphical callers instead show
the reason and wait for a user relay/cancel choice. There is no separate fixed
Mode 2 path. `Session::begin` retains a one-second default; graphical callers use
an explicit preparation budget of up to five seconds.

The existing protobuf envelope (`NativeP2pV1`, field 1000, envelope version 1)
and registration fields 1000/1001 are retained to avoid another upstream schema
change. That envelope version is not an additional capability. The signed JSON
uses the domain `rustdesk-native-udp-punch\0`; old experiment signatures cannot
be mistaken for the new capability. Tickets repeat the negotiated capability.

## Modules and flow

- `protocol` and `coordinator`: signed capability, participant admission,
  sealed probe keys, replay/quota checks and one session lease per device.
- `stun`: two to four distinct IPv4 destination observations using one retained
  UDP socket and `stun.easyvoip.com:3478` plus its alternate endpoints.
- `interfaces` and `candidates`: active physical IPv4 adapters, on-link LAN
  filtering and authenticated TCP source-IP verification.
- `strategy`: NAT evidence, five strategy families and bounded outcome scores.
- `hole`: authenticated probes, shared budgets, TTL restoration and socket cleanup.
- `transport`: bounded RPCs, preparation, polling and explicit awaited cancellation.
- `progress`: optional secret-free observations and bounded structured reasons
  carried inside the existing signed Error string, without altering Plan/Ticket.

The mandatory two STUN destinations and optional crossed IP/port observations
share six seconds; each optional observation has at most 500 ms. TCP NAT type
never vetoes this independent UDP path. Prediction needs at least three valid
observations for the same public IP, a port span of 1..5, and strictly increasing
or decreasing ports. Alternating destination-specific pools are not predictable.
This is a conservative heuristic, not proof that a gateway will allocate its next
port deterministically.

Each endpoint can add at most four authenticated TCP source observations within
a shared two-second budget. The server verifies the device signature and session
membership before admitting an IP, and retains at most four public exits per
participant, only for that session. STUN addresses alone never prove ownership.
Unverified UDP exits are removed; an empty result ends this bounded attempt. UDP-only egress that authenticated TCP cannot observe is an
explicit coverage limit. Port deltas are never combined across public IPs.

Each endpoint advertises at most eight physical-adapter RFC1918 candidates using
the retained socket's port. The receiver only tries exact candidate endpoints in
its own physical interface's directly connected subnet, excluding its own IPs,
network and broadcast addresses. LAN probing is authenticated and limited to
750 ms. TUN, loopback and virtual adapters are excluded by platform enumeration.
A physical public interface matching the observed UDP IP and port is preferred
as the Mode 0 receiver. Its endpoint must also pass TCP source verification.

## Strategy families

| Mode | Eligibility | Behavior |
| --- | --- | --- |
| 0 / Direct | Both EasyNAT, or a physical public receiver | Ordinary mutual probes; both directions; receiver TTL 7, 4 or OS default; sender delay 0, 5 or 10 s. |
| 1 / Predict | EasyNAT plus predictable HardNAT | HardNAT sender, immediate or 2 s delay; EasyNAT predicts at most 21 ports; receiver TTL 7, 4 or default. |
| 2 / Birthday | EasyNAT plus HardNAT | EasyNAT waits 3 s then probes 1000 random targets; HardNAT opens 256 extra sockets; receiver TTL 7, 4 or default. |
| 3 / BothPredict | Two predictable HardNATs | Both predict ports; both direction choices; receiver TTL 7, 4 or default. |
| 4 / Mixed | Two HardNATs, at least one predictable | Predictable sender waits 3 s and probes random ports; receiver opens 256 extra sockets and predicts a radius of at most 2; TTL 7, 4 or default. |

The 28 role/TTL/delay combinations follow the fixed reference version (Mode 4's
code specifies 3 s despite an older 2 s comment). Two unpredictable HardNATs
without a usable LAN path return an explicit no-strategy reason. Only one strategy
is selected per round. GUI retry policy lives in the client controller; this
library never starts a persistent retry tunnel.

History stores at most 1024 network-profile pairs, expires after one hour, and
never caches winning ports. Selection subtracts one point exactly once; only
the caller, after KCP plus RustDesk's device-identity secure handshake, reports
success for two points. Scores are bounded at -10..10 and reset after exhausting
eligible choices. Polling does not penalize again; confirmation consumes the
session, so it cannot be rewarded twice. Password/confirmation still follows the
secure handshake normally. Diagnostic UDP or KCP echoes never reward history.

## Authentication and hard bounds

Requests are signed with registered device Ed25519 keys. hbbs verifies freshness,
nonce reuse, the server admission key and session membership. Server-signed
tickets bind both device IDs and deliver one random 32-byte key through sealed
boxes. UDP probes authenticate session, direction and nonce with HMAC-SHA512/256.
Only authenticated responses from approved IPs (exact ports for LAN) may win.
The winning socket remains open for KCP; losing tasks/sockets are cancelled.

- 60 s maximum signed lease, including preparation and KCP; LAN and WAN
  share at most 38 s of probing, with at least 3 s reserved for KCP.
- One attempt per device; at most 257 traversal sockets per endpoint.
- 1000 unique random IP/port combinations shared across all exits, weighted by
  observed UDP exit frequency; ports 1024..65534, approximately 15 ms apart.
  Exits do not multiply the budget.
- At most 8192 authenticated probe datagrams per endpoint/attempt, including
  initial primers, LAN probes and replies; TTL always restored.
- At most 64 server sessions, 4096 device capability records and 512 signed
  requests per device per 60 s. Recent signed heartbeats are required.

Cancellation drops readers immediately and sends a bounded best-effort cancel
RPC; peer cancellation polling is once per second, with a one-second RPC bound.
After KCP accept the receiver hands cancellation ownership to the caller until
its secure handshake completes. Session expiry covers crashes or lost cancels.
Explicit proxy, WebSocket and forced-relay choices keep their original behavior.
No media, UI, Android permission/JNI, relay data forwarding or upstream KCP code
is changed by this expansion.

## Diagnostics and validation

From the common checkout:

```text
cargo test --locked --manifest-path native-p2p/Cargo.toml
cargo build --locked --manifest-path native-p2p/Cargo.toml --bin native-p2p-probe
native-p2p-probe discover
native-p2p-probe listen TEST_HOST:22116 TEST_SERVER_PUBLIC_KEY
native-p2p-probe connect TEST_HOST:22116 TEST_SERVER_PUBLIC_KEY LISTENER_ID
```

The UDP tool proves only authenticated UDP echo. The client's separate
`tools/native-p2p/diagnostic` crate uses this same module and the production
`KcpStream` source, validates server-signed peer keys and a fresh signed challenge,
and verifies a 64 KiB KCP echo. Its `authenticated-kcp-diagnostic` result still
is not a RustDesk desktop/password/permission acceptance result. Neither tool
reports success to server scoring. Always start the receiver before the caller.

`tools/native-p2p/nat-lab.py` creates uniquely named Linux network namespaces,
private hbbs/STUN instances, real SNAT/conntrack and optional netem loss. It never
changes host routing/firewall. For LAN/public-interface fixtures only, the
standalone diagnostic calls `Session::punch_on` with explicitly reported veth
addresses; RustDesk always calls `punch` to enumerate actual physical adapters.
Fixtures validate candidate handling, not hardware-adapter discovery.

Keep TUN enabled on real endpoints. Verify actual mappings, transport, desktop
frames and relay traffic; a DIRECT rule name or a single UDP packet is not proof
of P2P remote control. Real Windows acceptance, Android builds and Android real
device tests must be reported separately. Keep the client/server common baselines
separate and cherry-pick only this feature patch between them.

The optional `Session::probe` observer leaves the lease with its caller so normal
cleanup can await `Session::close`. Probe futures run under their owner rather
than detached tasks: cancellation drops losing sockets and restores TTL before
a new round. `Drop` retains a short best-effort notification only for emergencies.
A signed ticket can shorten, never extend, the caller's monotonic deadline.
