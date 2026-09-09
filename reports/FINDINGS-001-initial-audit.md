# Findings 001 — Initial Network Security Audit

**Target:** `samples/game-project` — Flax 1.12.6912, custom packet layer (`Game.Shared.Network`)
**Date:** 2026-07-31 · **Method:** static analysis of network ingress paths (real examples, not theory)
**Verdict:** codebase is mid-construction; netcode is NOT wired into any scene. No server can start today. The few ingress paths that exist have 2 HIGH + 3 MED issues.

---

## Critical finding (blocks ALL testing)

**NET-0 — There is no runnable server.**
- `NetworkBootstrapBase` / `LobbyScaffold` / `LobbyRosterNetworkSessionCoordinatorBase` / `NetworkSessionCoordinatorBase` are NOT attached in any `.scene` file (verified: 0 matches in all 6 scenes).
- `Content/GameSettings.json` `FirstScene` = `885078a148cb0336dc98e7837f184263` — **no scene file with that ID exists** (scenes on disk: Arena, ArenaScene, HelloWorld, PhysicsPlayground, TestCoreFix, VerificationTest). The game cannot even load its startup scene.
- `NetworkCombatSync` is attached in ArenaScene but it is **broadcast-only** (server→client); nothing ever calls `NetworkManager.StartServer()`.
- Consequence: today there is **nothing listening on 7777 to attack**. Before any aggressive testing, the server must be wired (a lab scene + coordinator + scaffold, or a dedicated server project).

---

## Vulnerabilities found (real code, real line numbers)

### NET-1 · HIGH · Unbounded allocation on packet count (memory DoS)
`NetworkPackets.cs:133-145` (`PlayerListPacket.Deserialize`) and `NetworkPackets.cs:210-223` (`PlayersTransformPacket.Deserialize`)
```csharp
var count = msg.ReadInt32();
for (int i = 0; i < count; i++) { ... }   // count comes straight from the wire
```
- A single packet claiming `count = 1,000,000,000` forces allocation attempts + exception handling per packet. Each exception is caught (`PacketRegistry.cs:100`), so the server doesn't crash — it burns CPU/allocation churn. A flood of these = CPU DoS. On the client, the same packet can OOM a player's machine.
- `PlayerList` is server→client, so the attack vector is *malicious server* → crashes players. `PlayersTransform` is client→server — the vector a *malicious client* uses against the server.
- **Fix:** cap `count` (e.g. 64 for player lists, 128 for transforms) before allocating; drop the packet on overflow.

### NET-2 · HIGH · Username length claimed on the wire is allocated before sanitizing
`NetworkPackets.cs:64` (`ConnectionRequestPacket.Deserialize`):
```csharp
Username = msg.ReadString();          // allocates what the length-prefix claims (up to int32.MaxValue)
```
then only `LobbyScaffold.cs:145` `SanitizeUsername()` caps it **after** allocation.
- Malicious client sends `ConnectionRequest` with username length-prefix = 2^30 → server allocates ~1GB per handshake. No rate limit on handshakes (see NET-4) → repeated = OOM.
- **Fix:** cap at read time (`MaxUsernameLength` + margin), reject length-prefix > cap before allocating. Same pattern for every `ReadString`.

### NET-3 · MED · No server-side transform validation exists
`NetworkPackets.cs:185-224` — `PlayersTransformPacket` is defined and has a client→server ingress route, but no handler anywhere validates:
- per-packet rate (transforms per second per client),
- max distance delta (teleport), max speed (speed hack), dead-reckoning plausibility,
- whether the actor being moved belongs to the sender (spoofing another player's ID).
- **Fix (must exist before transforms ship):** server-authoritative movement rules — clamp deltas to `maxUnitsPerSecond × dt`, verify actor ownership per connection, rate-limit.

### NET-4 · MED · No rate limit on connection handshake / global packet ingress
`LobbyScaffold.cs:128` — `ConnectionRequest` handler has no throttle: a client can loop connect→request→disconnect to burn CPU. Also no per-connection packets-per-second budget on `PacketRegistry.Receive` (`PacketRegistry.cs:40`).
- **Fix:** per-IP/per-connection request budget (e.g. 3 handshakes/min), and a global PPS cap per connection with drop.

### NET-5 · MED · `CombatEventType` byte is trust-mapped to enum
`NetworkCombatSync.cs:461` — `(CombatHitKind)msg.ReadByte()` and `(CombatEventType)msg.ReadByte()` cast wire bytes to enums without range checks; downstream switches may hit unexpected values. Low real risk today (broadcast-only), but harden when client ingress for combat exists.
- **Fix:** validate `rawEventType < Enum.GetValues().Length`, reject otherwise.

---

## What is already solid (verified in code)
- `ConnectionRequest` token: length-capped at wire level (`NetworkPackets.cs:47,66-72`), fail-closed auth default (`LobbyScaffold.cs:263-271`).
- Chat: length clamp + auth-map gate + server-stamped SenderID + per-sender rate limit (`LobbyScaffold.cs:196-231`).
- Auth map evicted on disconnect (`LobbyScaffold.cs:345-347`), chat throttle entry evicted too.
- `PacketRegistry.Receive` wraps handler execution in try/catch (`PacketRegistry.cs:100`) — exceptions don't kill the loop.
- `NetworkCombatSync`: broadcast-only (no client ingress), HP tracker bounded by `MaxTrackedTargets` (`NetworkCombatSync.cs:297`).
- Combat sync logs + queues on client, applies on main thread — no obvious desync/overflow on that path.

---

## Skills/toolchain this audit required (what the sandbox needs)
1. **Protocol reading** — map every ingress path: packet ID routing (`PacketRegistry`), deserializers (`NetworkPackets`), handlers (`LobbyScaffold`). Skill: reading netcode like an attacker.
2. **Allocation-flow tracing** — the username/length issues are only visible by tracing read→allocate→validate order. Skill: "lengths validated before or after allocation?"
3. **State-machine review** — auth map, rate windows, eviction: the lobby's state transitions.
4. **Scene/asset forensics** — found NET-0 by cross-referencing scene GUIDs in `GameSettings.json` vs scenes on disk.
5. Next phase (tooling): rogue client (Flax test project), boofuzz-style field fuzzing for NET-1/NET-2 PoCs, Wireshark loopback capture on 7777, PowerShell orchestrator (server spawn → attack → alive-check → report).

## Recommended order of operations
1. Fix NET-1, NET-2, NET-4 in the game code (small, high-value) — lab will re-test them.
2. Wire the server (lab scene or dedicated server project) so aggressive testing can start.
3. Build rogue client + fuzzers in this lab folder; run NET-1/NET-2 PoCs against the real server.
4. Add transform validation (NET-3) as a *requirement* before movement replication ships.
