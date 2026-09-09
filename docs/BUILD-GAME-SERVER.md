# BUILD-GAME-SERVER — how to build a better game server (defense cookbook)

What the attack lab proved we must build, plus research-backed design rules.
Full specs: SECURITY-BY-DESIGN.md (rules), WIRE-FORMAT.md (wire),
SECURED-SERVER.md (hosted topology), SECURITYPACK-PLUGIN.md (pack build).

## 1. Server-authoritative or lose (the only real rule)

(Fox-IT game security research; RejiDev packet RE guide; SECURITY-BY-DESIGN
Rule 1.) A client that sends raw positions/health/damage results is telling
you it is client-authoritative — packet edits are then trivially cheat
vectors (TRICKS A3/A4). Design: clients send **inputs + tick**, server
recomputes state, sends corrections. Network manipulation is the one cheat
class the server can always see — assume the client is a hostile process.

## 2. The wire protocol must survive hostile input

- **Frame everything** (length-prefix or ENet framing), reject oversized
  packets before deserialization (MetricsGuard budgets, NET-4).
- **Never trust ids/fields**: range-check every uint; reject unknown packet
  ids explicitly (our Tripwires 251-255 + unknown id handling) instead of
  letting them hit switch defaults.
- **Auth = challenge-response** (TRICKS A2): nonce → response → session
  token riding every packet; never accept a client-supplied version/token
  without verification. Replay-protect with per-session sequence (Envelope250
  HMAC + replay window is the in-repo answer).
- **Timing-safe comparisons** for anything secret (FixedTimeEquals) — and
  test it (M-04).

## 3. Rate and budget everything (cheap, huge effect)

Per-session budgets for bytes/packets/actions (MetricsGuard), global caps for
connect floods, chat/action rate limits. Budgets trip → shadow/quarantine
(FlagRouter T0 thresholds), never crash. DoS acceptance test is the lab's
Phase 4 (PLAYBOOK-GAME).

## 4. Detection is layered, response is graded

T0 thresholds (deterministic) → behavioral ML (SentinelT1 ONNX, pattern from
the proven FlaxMCP pipeline: advisory-only, receipts, graceful degrade) →
dossier + flag workflow (USER-DOSSIER). Never auto-ban on a single signal;
flag → shadow → review → confirm.

## 5. Ops topology that survives cheating (SECURED-SERVER)

- Public port only for gameplay (UDP 7777 via tunnel edge); admin/MCP ports
  never leave the box (MCP-SECURITY B4).
- Process separation: live / quarantine lobby / decoy twin, env-var role,
  separate DBs — a compromised lobby cannot see the main game.
- Keys: `FLAXMCP_GAME_HMAC_KEY` ceremony, per-release rotation, never in
  repo; thresholds and model paths env-var driven, process-immutable.

## 6. Research-backed references (verified 2026-08-01)

- RejiDev/game-hacking-guidelines — packet RE workflow + common opcode/field
  patterns to defend against (we used its heuristics as our test generator).
- Fox-IT "Game Security" — cheat taxonomy + authoritative-server argument.
- heroiclabs/nakama, agones (K8s game servers) — server-authoritative
  backends + scaling patterns for when the game grows.
- awesome-game-security (gmh5225) — the ongoing reference index.

## 7. Acceptance (measurable)

- All lab Phase 0-4 probes: detected or rejected, 0 clean-flag FPR (sentinel
  gate <1%), server never crashes under fuzz/flood (boofuzz probe oracle),
  reserved-id scan trips tripwires, auth envelope rejects forged/replayed
  traffic (envelope test suite).
