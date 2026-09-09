# Game Server Security Research (defensive only)

Hardening notes for authoritative game servers + MCP plugin endpoints, learned from running a private Flax lab. No attack tools, no playbooks, no fuzzers here — defense and audit only.

## What's inside
- `docs/SECURITY-BY-DESIGN.md` — build-from-day-one rules: server authority, signed envelopes, versioning, strict parsing, telemetry thresholds, ops checklist.
- `docs/SERVER-SECURITY.md` — server hardening guide.
- `docs/SECURED-SERVER.md` — secured hosted-build blueprint (edge proxy, process split, key rotation, phased build).
- `docs/MCP-SECURITY.md` — MCP endpoint hardening: auth tokens, origin checks, permission tiers, supply-chain hygiene.
- `docs/BUILD-GAME-SERVER.md` — how to build the test server.
- `docs/AI-SENTINEL.md` — watchdog spec: threshold → anomaly → supervised tiers over session features, advisory-only, false-positive gate.
- `reports/FINDINGS-001-initial-audit.md` — sample audit findings format.
- `reports/RESEARCH-002-killed-by-cheaters-ai-threats.md` — threat research notes.
- `HARDENING-CHECKLIST.md` — 20-point checklist to run before any playtest.

## What is NOT here (stays private)
Attack playbooks, fuzzers, dissectors, fake servers/rogue clients, run logs, outreach docs. This repo proves I can think like a defender and ship the checklist, not the weapon.

## Author
Maxim Konovalov — Haifa. Part of `flax-game-studio` game-security work.
