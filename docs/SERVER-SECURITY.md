# Server Security — Day-One Plan (Flax 1.12 · ENet · UDP 7777)

Purpose: harden your multiplayer server **before** it goes public, and know exactly
what the attack tools in this lab will try against it. Research date: July 2026
(web-verified sources listed in each section). Ties back to
`reports/FINDINGS-001-initial-audit.md` (the weaknesses found in the current code).

The three truths that shape everything:

1. **ENet has zero known CVEs (20 years of scrutiny) — the protocol layer is not the
   weak point. Your app layer, the missing auth/encryption, and ENet's *defaults* are.**
2. **No encryption on the wire** means anyone can sniff session IDs, replay packets,
   or inject forged ones. ENet explicitly provides no authentication/encryption.
3. **Server-authoritative design is the only real anti-cheat.** Encryption, tokens,
   and rate limits all help, but a cheater running a modified client defeats all of
   them if the client can lie about outcomes (position, damage, HP).

---

## 1. P0 — do before first public exposure

| # | Control | Why |
|---|---|---|
| 1 | Set `maximumPacketSize = 8192` on the ENet host | Flax's `ENetDriver` never sets it → 32 MB default. A client can claim a 32 MB packet per peer. |
| 2 | Set `maximumWaitingData = 256 KB` per peer | Default 32 MB of queued reliable data per peer; a never-ACKing client fills server memory. |
| 3 | Set `duplicatePeers = 2` | Default 4095 → one spoofed IP can fill the entire peer table and block real joins. |
| 4 | Cap `ConnectionsLimit` (Flax `NetworkConfig`) at 16–64 | Becomes ENet `peerCount`. Protocol hard cap is 4095. |
| 5 | Lower `MessageSize` to ~1200 (default 1500) | Keeps packets under the 1500 MTU; fragmentation becomes rare. |
| 6 | Guard `PopEvent` against oversized receives | Driver copies `packet->dataLength` into a pooled 1500-byte message; validate before copy. |
| 7 | Validate every length/count field **before allocating** (username prefix, list counts, token length) | NET-1/NET-2: `count = ReadInt32()` then allocate = CPU/OOM DoS. Cap counts (64–128) and string lengths first. |
| 8 | Per-IP rate limits at session layer: 3–5 handshakes/min/IP, 100–200 packets/s/connection | ENet itself does not rate-limit; UDP = unauthenticated handshake churn forever. |
| 9 | Fail-closed packet handlers | `PacketRegistry` already try/catches — make the catch path reject the packet and continue; never swallow into unbounded retry. |
| 10 | Replace the static shared-secret connect check | The secret ships in every client binary and is sniffable. Per-session token + HMAC (`HMACSHA256(token | seq | payload)`) + replay window. See §4. |

## 2. P1 — first week after launch

11. Per-peer timeouts: `enet_peer_timeout(peer, 32, 5000, 30000)` — zombie peers reaped in ≤30 s.
12. `enet_host_bandwidth_limit(host, 1MB/s, 1MB/s)` — caps reliable window, starves slow-flood peers.
13. Handshake fast-fail: kick if not authenticated within 10 s of ENet connect.
14. App heartbeat every 5 s; drop after 3 missed (≤30 s). Don't rely on ENet pings alone.
15. Server-authoritative transform validation: clamp per-packet delta to `maxSpeed × dt`, verify actor ownership, rate-limit to 30–60 ticks/s. (NET-3/NET-4 territory.)
16. Enum/range validation on wire bytes: check `raw < count` before casting `(CombatHitKind)ReadByte()` (NET-5).
17. Run `dotnet-counters` + GC-memory alert from day one — allocation churn is the signature of a memory DoS.
18. Continuous ring-buffer capture (tshark/pktmon, §6) before an incident, not after.

## 3. P2 — structural improvements

19. Enable ENet CRC32 (`host->checksum = enet_crc32`) — corrupt-datagram detection, cheap.
20. Use the ENet `intercept` callback for raw-datagram admission control (cheap PPS filter before full parse).
21. Strike counter: log-and-kick on repeated malformed packets per connection (fuzzer detection).
22. No BinaryFormatter/reflection-based deserialization (CWE-502; removed in .NET 9 anyway). Keep explicit `NetworkMessage` codecs; if JSON, `System.Text.Json` with bounded `MaxDepth`/`MaxLength`.
23. Issued-session model: per-client random token, server-side expiry (~10 min idle), revocation on disconnect.
24. Run server as non-admin service; default-deny Windows Firewall, allow only UDP 7777 (+443 if WSS gateway).
25. Consider a WSS/TCP gateway (TLS-terminating reverse proxy → local UDP) where TLS is mandated.
26. Re-run the lab's PoCs (oversized counts, giant length prefixes) after every change — fix = survives the same test twice.

## 4. Auth — replace the shared secret

Current design (shared constant in the client binary) authenticates "someone who read
the binary" = everyone. Options, cheapest first:

- **A. HMAC-signed session ticket (no backend, ~1 day):** on connect, server issues
  `ticket = base64(userId | serverId | issuedAt | exp | nonce)` + HMAC-SHA256; verify
  with constant-time compare, check `exp` (1–2 h), one-time `nonce`. Steam's
  Encrypted Application Tickets use the same shape.
- **B. Opaque tokens via tiny HTTPS login endpoint (most robust, no backend):** a small
  ASP.NET Core `POST /login` mints a random 256-bit token (expiry + userId); the game
  server validates it in `NetworkManager.ClientConnecting`. Revocable, per-user, and
  the exchange happens over HTTPS, not on the ENet wire.
- **C. Platform auth when shipping on Steam:** `ISteamUser::GetAuthSessionTicket` /
  server-side `BeginAuthSession` (identity + ownership + VAC). Nearly free for a
  Steam-first game.

**Replay protection (all designs):** per-connection monotonic sequence numbers +
sliding window; timestamps in a freshness window; make state-changing actions
idempotent. If you add payload encryption, bind the nonce into the MAC.

## 5. Encryption — what it does and doesn't do

- **Does NOT stop a modified client.** The cheater reads plaintext before encryption and
  dumps keys from memory. Anti-cheat = server authority, not crypto.
- **DOES protect:** casual wire-sniffing, network-level packet injection/modification
  (real documented cheat vector), and tokens/passwords on the wire.

Options by effort:

| Option | Effort | Notes |
|---|---|---|
| Plaintext ENet | 0 | today's state; everything sniffable |
| **App-layer AEAD in .NET** | Low–med | `System.Security.Cryptography.AesGcm` (built into .NET 8); per-packet nonce = sequence counter; per-session key. Recommended next step. |
| DTLS around ENet | High (C#) | Godot ships this pattern (`dtls_client_setup`); no maintained C# wrapper exists. |
| Swap to Valve GameNetworkingSockets | Medium | AES-256-GCM + Curve25519 built in, C# NuGet; but per Valve: without PKI, still not MITM-proof. |

## 6. Server-side cheat detection (all from the server's view)

| Cheat | Detection | Difficulty | FP risk |
|---|---|---|---|
| Speedhack | Server clock only; `dist ≤ maxSpeed × serverDt × 1.2`; flag patterns (repeated violations), snap-back | Low | Medium (jitter) |
| Teleport/no-clip | Distance cap + geometry reachability; snap back to last valid position | Low–med | Medium (platforms, falling) |
| Damage/insta-kill | Architectural: server computes damage from validated hits (raycast/rewind, ammo/range/cooldown) | Low (design) | Low |
| Inventory/economy | All grants server-side; validate item ID/cost/cooldown; log for post-match audit | Low–med | Low |
| Packet replay | App-level seq + sliding window; idempotent handlers | Low | Low |
| Lag switch | RTT/loss telemetry (ENet gives you `PeerStatistic`), death-on-disconnect rule, heartbeat timeouts | Medium | Medium — warn, don't auto-ban |
| Aimbot | Server-side stats (yaw flicks, reaction <100 ms, 100% accuracy); flag-for-review | High | High — never auto-ban |
| Wallhack/ESP | **Not detectable server-side.** Mitigate with fog-of-war/relevancy: only send data the client could observe. | — | — |
| Memory hacks | **Neutralized by server authority** — freezing client HP does nothing if the server owns HP. | — | — |

## 7. Rate limiting numbers (token buckets, per peer + per message type)

- Movement/input: capacity 10–15, refill 35–40/s (= tick rate + 20% jitter).
- Chat: capacity ~20, refill ~5/s (1–2 msg/s sustained). Separate bucket so chat spam can't starve movement.
- Friend/report: 3–5/min, weighted (report = 2–5 tokens), per-target caps.
- Connections: 1 per 3 s per IP (generous for NAT).
- Layered: global cap → per-IP → per-peer → per-message-type; run before gameplay processing;
  return a "throttled" flag to legit clients. In .NET: `System.Threading.RateLimiting`
  (`PartitionedRateLimiter`, token bucket) works outside ASP.NET.

## 8. ENet config summary (patch `ENetDriver.cpp` `Listen()`)

```c
_host = enet_host_create(&address, _config.ConnectionsLimit, 1, 0, 0);
_host->duplicatePeers     = 2;              // 1 IP ~ 1 player  (default 4095)
_host->maximumPacketSize  = 8192;           // cap reassembly    (default 32 MB)
_host->maximumWaitingData = 256 * 1024;     // cap peer queue    (default 32 MB)
_host->checksum           = enet_crc32;     // corruption detection
enet_host_bandwidth_limit(_host, 1024*1024, 1024*1024);   // 1 MB/s each (default 0 = unlimited)
// on ENET_EVENT_TYPE_CONNECT:
enet_peer_timeout(peer, 32, 5000, 30000);
```

| Tunable | Default | Recommended | Effect |
|---|---|---|---|
| `duplicatePeers` | 4095 | 2 | blocks single-IP peer-table fill |
| `maximumPacketSize` | 32 MB | 8192 | caps reassembled packet work |
| `maximumWaitingData` | 32 MB | 256 KB | caps unsent reliable queue per peer |
| bandwidths | 0 (unlimited) | 1 MB/s each | caps reliable window; starves flooders |
| `mtu` | 1400 | 1200–1400 | keeps fragments rare |
| `peerCount` | 32 (Flax default) | 16–64 | hard concurrent-cap |
| timeouts | default | 32 / 5000 / 30000 ms | reaps zombies in ≤30 s |
| `channelLimit` | 1 | 1 (unchanged) | Flax only uses channel 0 |

Also in `NetworkConfig.h`: `MessageSize` 1500 → 1200; `MessagePoolSize` 2048 → 4096–8192
(hitting the pool limit **crashes the process** — size it for PPS cap × clients).

## 9. Monitoring & incident response

- **Log (structured, per connection):** connect/disconnect/timeouts + IP, handshake→auth
  latency, per-client packet counts & drops, rejected packets (id, reason), rate-limit hits, handler exceptions.
- **Capture from day one (Windows, no install needed):**
  ```powershell
  pktmon filter remove; pktmon filter add -t UDP -p 7777
  pktmon start -c --pkt-size 0; pktmon stop
  pktmon etl2pcap PktMon.etl -o capture.pcapng
  ```
  Or tshark ring buffer: `tshark -i loopback -f "udp port 7777" -b filesize:100000 -b files:10 -w C:\captures\enet.pcapng`
- **Flood detection:** baseline normal PPS for your player cap; alert at 5–10× baseline;
  watch GC alloc rate via `dotnet-counters` (memory-DoS signature).
- **Kill-switch (pre-tested):**
  ```powershell
  netsh advfirewall firewall add rule name="BLOCK-ATTACKER" dir=in action=block remoteip=<ip> protocol=UDP localport=7777
  Stop-Process -Name <GameServer> -Force
  ```

## 10. What the lab will throw at this server (test matrix)

| Lab tool | What it does | Validates |
|---|---|---|
| `flax_enet.py --mode connect` | legit handshake+auth | baseline works |
| `--mode craft` | exact PoC payloads (NET-1 `07 ca9a3b`, NET-2 `01 ffff`, ...) | §1 #7, #1–2, #6 |
| `--mode packet-soup` | random ids | §1 #9, §3 #21 |
| `--mode flood-connect` | ~136k CONNECT/s | §1 #8, §2 #13, §8 tunables |
| `--mode flood-request` | handshake churn | §1 #8 |
| `--mode chat-flood` | spam | §7 chat bucket |
| `--mode fuzz` + boofuzz | mutation fuzzing | §1 #7/#9, §3 #22 |
| Wireshark dissector | session-id sniffing (2-bit guess = 25%/try) | §4–5 decisions |
| replay tests | state-changing message replay | §4 replay protection |

## 11. Reading list (2025–2026, verified)

- Server authority: AccelByte (Apr 2026) `accelbyte.io/blog/server-authoritative-logic-to-prevent-cheating` · drcodes (Sep 2025) · gistre EPITA history of anti-cheat (Nov 2025, Fall Guys/GTA case studies) · arXiv 2607.04336 (aimbot detection, Jul 2026)
- Networking classics: Gabriel Gambetta client-server architecture · Valve lag compensation wiki
- Auth: Steamworks auth docs · PlayFab Authenticate Session Ticket · authgear HMAC (Feb 2026) · bugnet.io replay (Jun 2026)
- Transport: Godot ENet+DTLS article · Valve GameNetworkingSockets (issue #183 MITM caveat) · `gamedev.stackexchange.com/questions/115615`
- Rate limits: GitConnected token-bucket design (Nov 2025) · mineguard.pro per-IP throttling (Mar 2026)
- Industry: OWASP Game Security Framework (public review draft, stable target Q4 2026) · CCP "Server-Side Fog of War" (Unreal Fest Stockholm 2025) · USENIX Sec 2026 XGuardian
- ENet: `enet.bespin.org` (docs) · `github.com/lsalzman/enet` (host.c defaults) · lsalzman/enet issue #278 (CONNECT flood window, Sep 2025)
