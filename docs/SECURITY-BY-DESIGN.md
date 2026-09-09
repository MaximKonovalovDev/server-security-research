# SECURITY-BY-DESIGN — Building Flax Multiplayer Hard-to-Hack from Day One

**Applies to:** `samples/game-project` (Flax 1.12.6912, custom packet layer
`Game.Shared.Network`), and by extension any new Flax multiplayer game.
**Why this exists:** every game that died to cheating (RYL, New World, AoS,
Hypixel-adjacent cases — see `reports/RESEARCH-002` / `-003`) died the same
way: trusted client + weak validation + slow response. This doc turns those
lessons into build-from-day-one rules with Flax-specific hook points.

**The honest ceiling first:** at indie scale you cannot stop a determined
cheater — client memory + binaries are fully in their hands. You *can* make
hacking your game **not work** (server authority) and **get caught**
(telemetry). That combination kills the cheat market for a game, which is
the real victory condition.

---

## Rule 1 — Server authority (90% of the work)

**The server owns all state: HP, position, inventory, damage, spawns,
timers. The client sends intent only. The server simulates, validates,
decides.**

- Combat: server computes damage from validated inputs (range, LOS, cooldown,
  facing). Never apply a damage value sent by a client. AoS's protocol docs
  carry the same warning verbatim ("server should verify that this is
  possible to prevent abuse" — for hits).
- Movement: client reports its transform; server clamps to
  `maxUnitsPerSecond × dt`, verifies no-clip bounds and *ownership* (see NET-3
  below). Teleport/speed-hack signatures are the easiest flags in telemetry.
- Economy (when it exists): every value-changing op is server-computed,
  logged, auditable. Dupes have a *rollback window* — detect fast or never
  roll back (New World / WoW lesson, ARSENAL E5).
- Chat: already mostly done (`LobbyScaffold.cs:196-231`: length clamp, auth
  gate, server-stamped SenderID, per-sender rate limit) — the pattern to
  copy everywhere.

### Flax hook points (current code, from FINDINGS-001)
| Rule piece | Where it lives now | What to do |
|---|---|---|
| Validate before dispatch | `PacketRegistry.Receive` (PacketRegistry.cs:40) | All validation gates go in/around dispatch; keep the try/catch (:100) but make bad packets drop, not just log |
| Count caps before alloc | `NetworkPackets.cs:133-145, 210-223` | NET-1: cap `count` (64 player list / 128 transforms) before `for` loops |
| String caps at read time | `NetworkPackets.cs:64` | NET-2: cap length-prefix before `ReadString` allocates (24 chars + margin), reject >cap. Same for every future `ReadString` |
| Enum range checks | `NetworkCombatSync.cs:461` | NET-5: `raw < Enum.GetValues().Length` before casting |
| Movement validation | none (NET-3, MED) | Must exist *before* transform replication ships — see below |
| Handshake throttle | none (NET-4, MED) | Per-IP handshake budget, see Rule 5 |

### Movement validation (NET-3) — required before transforms ship
```csharp
// Server, in the transform ingress handler:
if (msg.PlayerId != session.PlayerId)          // ownership: no spoofing another player
    return Drop("transform-owner-mismatch");
var dt = now - session.LastTransformTime;      // monotonic server time, not client time
session.LastTransformTime = now;
var delta = (msg.Position - session.LastPosition).Length();
if (dt > 0 && delta > MaxUnitsPerSecond * dt * 1.25f)  // 1.25 = jitter headroom
    return Drop("transform-speed-exceeded");
if (Physics.OverlapSphere(msg.Position, Radius).Count == 0)  // no-clip check (per map)
    return Drop("transform-out-of-bounds");
session.LastPosition = msg.Position;
```

---

## Rule 2 — Per-session integrity (kills 80% of tools)

**Server assigns player identity. Every critical packet carries a
session-authenticated envelope.**

1. **Server-assigned IDs.** The client never supplies its own player/actor
   ID — the server mints a `Guid` (ConnectionResponse already does this) and
   every packet is bound to the connection, not to an ID in the payload.
2. **Session key + HMAC envelope.** At connect, both sides derive a session
   key; critical packets (movement, combat, economy) get a MAC. This kills:
   WPE-style filters (can't re-MAC without RE), MITM proxies (same), replay
   (counter), and forged bots (don't know the key).
3. **Monotonic counter.** Per-session `seq` in the envelope; server rejects
   out-of-order/duplicate seq → replay dead.

### Design (honest about limits)
The client must be able to compute MACs, so key material lives in the client
build — **this is a speed bump and an anti-accident layer, not a wall.** The
wall is Rule 1. The MAP is: it raises the cost of building a working cheat
from "download WPE" to "reverse the binary and extract the key" — which is
exactly where the cheat market decides a game isn't worth it.

```csharp
// 1. Key derivation at connect (server + client, same inputs)
//    sharedVersionKey: per-game-build secret, obfuscated in the client binary
var sessionKey = HMACSHA256(sharedVersionKey,
    concat(connectionId /* server-assigned Guid */, clientNonce /* from ConnectionRequest */));

// 2. Envelope layout (new packet IDs, so existing 1-8/200 stay parseable by the lab)
//    id=250 AuthEnvelope C->S:
//      u8 innerId | u32 LE seq | payload... | u32 LE mac(innerId,seq,payload,extra)
//    extra = sessionKey-derived per-session random; MAC truncated to 4-8 bytes is fine here.
//    (HMAC-SHA256 over innerId+seq+payload, truncated to 4 bytes, ~microseconds/packet)

// 3. Server verify, first thing in PacketRegistry.Receive:
var mac = HMACSHA256(session.PeerKey, concat(innerId, seq, payload)).Take(4);
if (!FixedTimeEquals(mac, receivedMac)) return Drop("bad-mac");
if (seq <= session.LastSeq) return Drop("replay-seq");   // strict monotonic per packet type
session.LastSeq = seq;
```

Keep the raw `connectID` from the ENet handshake in mind: it is already a
per-connection random (CONNECT body @36, WIRE-FORMAT.md §1) — usable as an
additional input to key derivation if Flax exposes it to C# (verify at
`NetworkBootstrapBase`/`NetworkConnection` level in 1.12).

---

## Rule 3 — Protocol design from day one

1. **Version byte in the handshake.** Add `u8 ProtocolVersion` to
   ConnectionRequest/Response now, while the layer is small. Bump on any
   layout change. Old hacked clients break on the next patch — the same
   tactic NCSoft used against L2 packet tools (RESEARCH-003 §1.4).
2. **Obfuscate opcodes per version.** At build time, permute packet IDs with
   a version-specific XOR table (1→table[1]). Keeps debugging sane, breaks
   published packet lists. Apply to payload field order too if you want a
   second layer.
3. **Strict parsing everywhere:**
   - explicit lengths; caps on every message (NET-1/NET-2 fixes above);
   - reject unknown packet IDs (already logged — make it *drop* + count);
   - validate enums (NET-5); no unbounded allocations (the two HIGHs).
4. **Fixed-size structs where possible** (your 44 B/entry transform is good).
   Document internally, **never publish** (AoS → 3 bot clients because its
   protocol was public, RESEARCH-003 §3).
5. Keep packet IDs 1-8 + 200 stable (lab tooling + dissector depend on them);
   add new features on new IDs (e.g. 250 auth envelope, 251+).

---

## Rule 4 — Telemetry from day one (the catch-hackers half)

Cheap per-session counters + a flag queue. No ML needed at launch — thresholds
catch the classics; a human reviews flags (upgrade path: `AI-SENTINEL` spec).

```csharp
public sealed class SessionMetrics {
    public long   Packets, Bytes;
    public double Pps, ByteRate;            // rolling windows
    public float  MaxDelta, MaxSpeed;       // movement outliers
    public float  HitAccuracy;              // combat
    public int    DropReasons;              // increments per validation drop
    public float  PingJitter;
    // serialize to JSON on disconnect and on every flag; rotate daily
}
```
Flag thresholds (from ARSENAL E4/F4 "tells"):
- packet bursts coinciding exactly with engagements (state manipulation / lag switch)
- impossible coordinates or speeds (exploits) — already dropped by NET-3, but *count* them
- suspiciously consistent reaction windows (AI aimbots, later)
- frame-perfect repetition for hours (macros, later)
- drop-reason counters climbing (someone probing = WPE/fuzz — tell the user's
  own lab traffic from attacks via a local flag)

Never auto-ban on a flag alone: **flag → shadow → human review → ban.**
Wrong bans kill trust (Hypixel's high-ping false bans).

---

## Rule 5 — Ops that are free

- **ENet config (verify exact property names in Flax 1.12):**
  `duplicatePeers = 2` (default is **unlimited** — verified in ENet source,
  ARSENAL F2), `ConnectionsLimit` 16-32, host bandwidth limits, peer timeouts
  left at defaults. All transport hardening is config, no code.
- **Per-IP handshake budget** (NET-4): e.g. 3 ConnectionRequests/min/IP —
  CONNECT floods at the game layer are the cheapest attack; this kills the
  churn.
- **Patch cadence beats ban waves:** new cheat variants appear ~4-6 h after a
  wave (2026 market data) — ship fixes in days, not months. Protocol version
  bump = every old tool dies instantly.
- **Community report channel** — exploits go viral; players are QA.
- **Account security** (when accounts exist): MFA / revocable tickets.
- **Never publish protocol docs or packet layouts** (see Rule 3.4).

---

## Web build (future) — add these
- Per-message auth (auth-once-at-handshake is the classic hole — ARSENAL F5).
- `Origin` header check on WS handshake (CSWSH).
- Short-lived tickets, invalidated on logout; tokens bound to connection ID.
- All state in server/relay; JS is 100% readable — HMAC there is
  anti-accident only; server validation is everything.

---

## Test matrix — the lab proves each control

| Control | Verify with (lab) | Expected after fix |
|---|---|---|
| NET-1/2 caps | `fuzz_enet.py` crafted counts/usernames | packet dropped, no alloc churn, server alive |
| NET-4 throttle | `flax_enet.py` connect-loop mode | 4th handshake/min rejected |
| NET-3 movement | `flax_enet.py` teleport/speed payloads | drops + metric flags |
| HMAC envelope | forge payload without MAC / wrong seq | `bad-mac` / `replay-seq` drops |
| Version bump | replay old-version handshake | rejected with version code |
| Flood resistance | flood modes + `attack-run.ps1` alive-check | server responsive, peers capped |

After each game-side fix, re-run `scripts/attack-run.ps1` — the exploit must
no longer reproduce. That is the acceptance criterion (ARSENAL F7).

---

## Priority order for the existing codebase
1. NET-1, NET-2, NET-4 (small, high-value — already identified)
2. NET-3 movement validation (before transforms ship)
3. Protocol version byte (now, while the layer is small)
4. Session key + auth envelope (Rule 2)
5. SessionMetrics telemetry (Rule 4) — pre-requisite for AI-SENTINEL later

*Reference: FINDINGS-001 (audit), WIRE-FORMAT.md (wire), RESEARCH-002/003
(cases + mechanics), ARSENAL.md (F2 ENet surface, F4 tells, F6 spec).*
